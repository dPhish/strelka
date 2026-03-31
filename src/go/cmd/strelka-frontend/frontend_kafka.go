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
<<<<<<< HEAD
<<<<<<< HEAD
=======
	"github.com/google/uuid"
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
	"github.com/google/uuid"
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a

	"github.com/target/strelka/src/go/api/strelka"
)

// ==============================
//  Kafka RAW message structure
// ==============================

type RawKafkaMessage struct {
<<<<<<< HEAD
<<<<<<< HEAD
	Id        string            `json:"id"`
	Filename  string            `json:"filename"`
	DataB64   string            `json:"data_base64"`
	Client    string            `json:"client"`
	Source    string            `json:"source"`
	Time      int64             `json:"time"`
	Meta      map[string]string `json:"meta"`
=======
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
	Id       string            `json:"id"`
	Filename string            `json:"filename"`
	DataB64  string            `json:"data_base64"`
	Client   string            `json:"client"`
	Source   string            `json:"source"`
	Time     int64             `json:"time"`
	Meta     map[string]string `json:"meta"`
<<<<<<< HEAD
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
}

// ==============================
//  Start Kafka Ingest
// ==============================

func (s *server) StartKafkaIngest(bootstrap, topic string) {
	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
<<<<<<< HEAD
<<<<<<< HEAD
		"bootstrap.servers": bootstrap,
		"group.id":          "strelka-kafka-ingest",
		"auto.offset.reset": "earliest",
	})

=======
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
		"bootstrap.servers":         bootstrap,
		"group.id":                  "strelka-kafka-ingest",
		"auto.offset.reset":         "earliest",
		"max.partition.fetch.bytes": 104857600,
		"fetch.message.max.bytes":   104857600,
	})
<<<<<<< HEAD
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
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

<<<<<<< HEAD
<<<<<<< HEAD
	// Decode base64 file
	data, err := base64.StdEncoding.DecodeString(raw.DataB64)
	if err != nil {
		log.Printf("Bad base64 for %s: %v", raw.Id, err)
		return
	}

	keyd := fmt.Sprintf("data:%v", raw.Id)
	keye := fmt.Sprintf("event:%v", raw.Id)
=======
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
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
<<<<<<< HEAD
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a

	// Deadline — like ScanFile
	deadline := time.Now().Add(2 * time.Minute)

	// Push file contents to Redis as ONE CHUNK
	p := s.coordinator.cli.Pipeline()
	p.RPush(ctx, keyd, data)
	p.ExpireAt(ctx, keyd, deadline)
<<<<<<< HEAD
<<<<<<< HEAD
	if _, err := p.Exec(ctx); err != nil {
		log.Printf("Redis write error: %v", err)
		return
	}

	log.Printf("📥 Stored file %s in Redis key %s", raw.Id, keyd)

	// Build request metadata
	reqObj := map[string]interface{}{
=======
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
	p.ExpireAt(ctx, keye, deadline)
	if _, err := p.Exec(ctx); err != nil {
		log.Printf("Redis write error for raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}

	log.Printf("📥 Stored file raw id=%s as task id=%s in Redis key %s", raw.Id, taskID, keyd)

	// Build request metadata
	reqObj := map[string]interface{}{
		"task_id": taskID,
		"id":      taskID, // important: Strelka workers usually use "id" to resolve data:<id> and event:<id>
		"raw_id":  raw.Id, // keep original external/message id for reference
<<<<<<< HEAD
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
		"attributes": map[string]interface{}{
			"filename": raw.Filename,
		},
		"client": raw.Client,
<<<<<<< HEAD
<<<<<<< HEAD
		"id":     raw.Id,
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
		"source": raw.Source,
		"time":   raw.Time,
	}

<<<<<<< HEAD
<<<<<<< HEAD
	// Add to Redis sorted task list
	reqJSON, _ := json.Marshal(reqObj)
=======
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
	if len(raw.Meta) > 0 {
		reqObj["meta"] = raw.Meta
	}

	// Add to Redis sorted task list
	reqJSON, err := json.Marshal(reqObj)
	if err != nil {
		log.Printf("Failed to marshal task raw id=%s task id=%s: %v", raw.Id, taskID, err)
		return
	}
<<<<<<< HEAD
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a

	err = s.coordinator.cli.ZAdd(
		ctx,
		"tasks",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: reqJSON,
		},
	).Err()
<<<<<<< HEAD
<<<<<<< HEAD

	if err != nil {
		log.Printf("Failed to add task %s → Redis: %v", raw.Id, err)
		return
	}

	log.Printf("📝 Added task %s to Redis sorted set 'tasks'", raw.Id)

	// Now wait for scanning result
	go s.waitForResult(raw.Id, keye, reqObj)
=======
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
	if err != nil {
		log.Printf("Failed to add task raw id=%s task id=%s to Redis: %v", raw.Id, taskID, err)
		return
	}

	log.Printf("📝 Added task raw id=%s task id=%s to Redis sorted set 'tasks'", raw.Id, taskID)

	// Now wait for scanning result
	go s.waitForResult(taskID, keye, reqObj)
<<<<<<< HEAD
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
}

// ==============================
//  Wait for result (same as ScanFile logic)
// ==============================

<<<<<<< HEAD
<<<<<<< HEAD
func (s *server) waitForResult(id, keye string, em map[string]interface{}) {
=======
func (s *server) waitForResult(taskID, keye string, em map[string]interface{}) {
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
func (s *server) waitForResult(taskID, keye string, em map[string]interface{}) {
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
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
<<<<<<< HEAD
<<<<<<< HEAD
			log.Printf("✔️  FIN received for %s", id)
=======
			log.Printf("✔️ FIN received for task id=%s", taskID)
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
			log.Printf("✔️ FIN received for task id=%s", taskID)
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
			break
		}

		// Merge event into metadata
<<<<<<< HEAD
<<<<<<< HEAD
		json.Unmarshal([]byte(lpop), &em)

		// prepare final JSON
		event, _ := json.Marshal(em)

		resp := &strelka.ScanResponse{
			Id:    id,
=======
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
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
<<<<<<< HEAD
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
			Event: string(event),
		}

		// Push to frontend responses channel (Kafka logger will pick it)
		s.responses <- resp

<<<<<<< HEAD
<<<<<<< HEAD
		log.Printf("📤 Delivered analysis for %s", id)
	}
}
=======
		log.Printf("📤 Delivered analysis for task id=%s", taskID)
	}
}
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
=======
		log.Printf("📤 Delivered analysis for task id=%s", taskID)
	}
}
>>>>>>> deaa4d6b97943f7c0e6fd31bf8e9e3c09d400c9a
