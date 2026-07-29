package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/target/strelka/src/go/api/strelka"
)

// ==============================
//  Kafka RAW message structure
// ==============================

type RawKafkaMessage struct {
	Id       string            `json:"id"`
	Filename string            `json:"filename"`
	DataB64  string            `json:"data_base64"`
	Client   string            `json:"client"`
	Source   string            `json:"source"`
	Time     int64             `json:"time"`
	Meta     map[string]string `json:"meta"`
}

const persistentTaskQueue = "tasks:persistent"

// ==============================
//  Start Kafka Ingest
// ==============================

func (s *server) StartKafkaIngest(bootstrap, topic string) {
	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":         bootstrap,
		"group.id":                  "strelka-kafka-ingest",
		"auto.offset.reset":         "earliest",
		"max.partition.fetch.bytes": 104857600,
		"fetch.message.max.bytes":   104857600,
	})
	if err != nil {
		log.Fatalf("Kafka consumer init error: %v", err)
	}

	if err := consumer.SubscribeTopics([]string{topic}, nil); err != nil {
		log.Fatalf("Kafka subscribe failed: %v", err)
	}

	log.Printf("🔥 Strelka Kafka Frontend started — consuming from topic: %s", topic)

	for {
		msg, err := consumer.ReadMessage(-1)
		if err != nil {
			log.Printf("Kafka read error: %v", err)
			continue
		}

		var raw RawKafkaMessage
		if err := json.Unmarshal(msg.Value, &raw); err != nil {
			log.Printf("Invalid Kafka message format: %v", err)
			continue
		}

		go s.processRawMessage(raw)
	}
}

// ==============================
//  Process each RAW message
// ==============================

func (s *server) processRawMessage(raw RawKafkaMessage) {
	ctx := context.Background()

	// Unique task ID per Kafka message, even if raw.Id repeats
	taskID := uuid.NewString()

	// Decode base64 file
	data, err := base64.StdEncoding.DecodeString(raw.DataB64)
	if err != nil {
		log.Printf("Bad base64 for raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}

	keyd := fmt.Sprintf("data:%s", taskID)
	keye := fmt.Sprintf("event:%s", taskID)

	// Build request metadata before writing non-expiring data to Redis.
	reqObj := map[string]interface{}{
		"task_id": taskID,
		"id":      taskID, // important: Strelka workers usually use "id" to resolve data:<id> and event:<id>
		"raw_id":  raw.Id, // keep original external/message id for reference
		"attributes": map[string]interface{}{
			"filename": raw.Filename,
		},
		"client": raw.Client,
		"source": raw.Source,
		"time":   raw.Time,
	}

	if len(raw.Meta) > 0 {
		reqObj["meta"] = raw.Meta
	}

	reqJSON, err := json.Marshal(reqObj)
	if err != nil {
		log.Printf("Failed to marshal task raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}

	// Kafka tasks wait indefinitely in a queue that the manager does not expire.
	// Store the data and queue member atomically so a failed enqueue cannot leave
	// non-expiring file data orphaned in Redis.
	enqueuedAt := time.Now()
	p := s.coordinator.cli.TxPipeline()
	p.RPush(ctx, keyd, data)
	p.ZAdd(
		ctx,
		persistentTaskQueue,
		&redis.Z{
			Score:  float64(enqueuedAt.UnixNano()) / float64(time.Second),
			Member: reqJSON,
		},
	)
	if _, err := p.Exec(ctx); err != nil {
		log.Printf("Failed to store and queue raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}

	log.Printf(
		"Stored and queued raw id=%s as task id=%s in Redis sorted set %q",
		raw.Id,
		taskID,
		persistentTaskQueue,
	)

	// Now wait for scanning result
	go s.waitForResult(taskID, keye, reqObj)
}

// ==============================
//  Wait for result (same as ScanFile logic)
// ==============================

func (s *server) waitForResult(taskID, keye string, em map[string]interface{}) {
	ctx := context.Background()

	for {
		lpop, err := s.coordinator.LPop(ctx, keye)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		if lpop == "" {
			continue
		}

		if lpop == "FIN" {
			log.Printf("✔️ FIN received for task id=%s", taskID)
			break
		}

		// Merge event into metadata
		if err := json.Unmarshal([]byte(lpop), &em); err != nil {
			log.Printf("Failed to unmarshal event for task id=%s: %v", taskID, err)
			continue
		}

		// prepare final JSON
		event, err := json.Marshal(em)
		if err != nil {
			log.Printf("Failed to marshal final event for task id=%s: %v", taskID, err)
			continue
		}

		resp := &strelka.ScanResponse{
			Id:    taskID,
			Event: string(event),
		}

		// Push to frontend responses channel (Kafka logger will pick it)
		s.responses <- resp

		log.Printf("📤 Delivered analysis for task id=%s", taskID)
	}
}
