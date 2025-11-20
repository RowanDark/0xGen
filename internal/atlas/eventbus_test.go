package atlas

import (
	"context"
	"testing"
	"time"
)

func TestNewBus(t *testing.T) {
	bus := NewBus()

	if bus == nil {
		t.Fatal("expected non-nil bus")
	}

	if bus.subs == nil {
		t.Fatal("expected subs map to be initialized")
	}

	if len(bus.subs) != 0 {
		t.Errorf("expected empty subs map, got %d entries", len(bus.subs))
	}
}

func TestBus_PublishSubscribe(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := bus.Subscribe(ctx, "test.topic")

	testData := "test message"
	bus.Publish("test.topic", testData)

	select {
	case event := <-ch:
		if event.Topic != "test.topic" {
			t.Errorf("expected topic 'test.topic', got '%s'", event.Topic)
		}
		if event.Data != testData {
			t.Errorf("expected data '%s', got '%v'", testData, event.Data)
		}
		if event.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestBus_MultipleSubscribers(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch1 := bus.Subscribe(ctx, "test.topic")
	ch2 := bus.Subscribe(ctx, "test.topic")
	ch3 := bus.Subscribe(ctx, "test.topic")

	testData := "broadcast message"
	bus.Publish("test.topic", testData)

	// All three subscribers should receive the event
	for i, ch := range []<-chan Event{ch1, ch2, ch3} {
		select {
		case event := <-ch:
			if event.Data != testData {
				t.Errorf("subscriber %d: expected data '%s', got '%v'", i+1, testData, event.Data)
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("subscriber %d: timeout waiting for event", i+1)
		}
	}
}

func TestBus_WildcardSubscriber(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wildcardCh := bus.Subscribe(ctx, "*")

	bus.Publish("topic1", "message1")
	bus.Publish("topic2", "message2")
	bus.Publish("topic3", "message3")

	// Wildcard subscriber should receive all three events
	receivedTopics := make(map[string]bool)
	for i := 0; i < 3; i++ {
		select {
		case event := <-wildcardCh:
			receivedTopics[event.Topic] = true
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for wildcard event")
		}
	}

	expectedTopics := []string{"topic1", "topic2", "topic3"}
	for _, topic := range expectedTopics {
		if !receivedTopics[topic] {
			t.Errorf("wildcard subscriber did not receive event for topic '%s'", topic)
		}
	}
}

func TestBus_SubscriberCount(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initially no subscribers
	if count := bus.SubscriberCount("test.topic"); count != 0 {
		t.Errorf("expected 0 subscribers, got %d", count)
	}

	// Add first subscriber
	ch1 := bus.Subscribe(ctx, "test.topic")
	if count := bus.SubscriberCount("test.topic"); count != 1 {
		t.Errorf("expected 1 subscriber, got %d", count)
	}

	// Add second subscriber
	ch2 := bus.Subscribe(ctx, "test.topic")
	if count := bus.SubscriberCount("test.topic"); count != 2 {
		t.Errorf("expected 2 subscribers, got %d", count)
	}

	// Add third subscriber
	ch3 := bus.Subscribe(ctx, "test.topic")
	if count := bus.SubscriberCount("test.topic"); count != 3 {
		t.Errorf("expected 3 subscribers, got %d", count)
	}

	// Different topic should have 0 subscribers
	if count := bus.SubscriberCount("other.topic"); count != 0 {
		t.Errorf("expected 0 subscribers for other.topic, got %d", count)
	}

	// Use channels to avoid unused variable errors
	_ = ch1
	_ = ch2
	_ = ch3
}

func TestBus_SubscriberCount_AfterCancellation(t *testing.T) {
	bus := NewBus()

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	ch1 := bus.Subscribe(ctx1, "test.topic")
	ch2 := bus.Subscribe(ctx2, "test.topic")

	if count := bus.SubscriberCount("test.topic"); count != 2 {
		t.Errorf("expected 2 subscribers, got %d", count)
	}

	// Cancel first subscriber
	cancel1()
	time.Sleep(50 * time.Millisecond) // Wait for cleanup goroutine

	if count := bus.SubscriberCount("test.topic"); count != 1 {
		t.Errorf("expected 1 subscriber after cancellation, got %d", count)
	}

	// Use channels to avoid unused variable errors
	_ = ch1
	_ = ch2
}

func TestBus_Topics(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initially no topics
	topics := bus.Topics()
	if len(topics) != 0 {
		t.Errorf("expected 0 topics, got %d", len(topics))
	}

	// Add subscribers to different topics
	ch1 := bus.Subscribe(ctx, "topic1")
	ch2 := bus.Subscribe(ctx, "topic2")
	ch3 := bus.Subscribe(ctx, "topic3")
	ch4 := bus.Subscribe(ctx, "*")

	topics = bus.Topics()
	if len(topics) != 4 {
		t.Errorf("expected 4 topics, got %d", len(topics))
	}

	// Check that all topics are present
	topicSet := make(map[string]bool)
	for _, topic := range topics {
		topicSet[topic] = true
	}

	expectedTopics := []string{"topic1", "topic2", "topic3", "*"}
	for _, expected := range expectedTopics {
		if !topicSet[expected] {
			t.Errorf("expected topic '%s' to be present", expected)
		}
	}

	// Use channels to avoid unused variable errors
	_ = ch1
	_ = ch2
	_ = ch3
	_ = ch4
}

func TestBus_Topics_AfterCancellation(t *testing.T) {
	bus := NewBus()

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	ch1 := bus.Subscribe(ctx1, "topic1")
	ch2 := bus.Subscribe(ctx2, "topic2")

	topics := bus.Topics()
	if len(topics) != 2 {
		t.Errorf("expected 2 topics, got %d", len(topics))
	}

	// Cancel first subscriber (topic1's only subscriber)
	cancel1()
	time.Sleep(50 * time.Millisecond) // Wait for cleanup goroutine

	topics = bus.Topics()
	if len(topics) != 1 {
		t.Errorf("expected 1 topic after cancellation, got %d", len(topics))
	}

	if topics[0] != "topic2" {
		t.Errorf("expected remaining topic to be 'topic2', got '%s'", topics[0])
	}

	// Use channels to avoid unused variable errors
	_ = ch1
	_ = ch2
}

func TestBus_ContextCancellation(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())

	ch := bus.Subscribe(ctx, "test.topic")

	// Publish before cancellation
	bus.Publish("test.topic", "message1")

	select {
	case event := <-ch:
		if event.Data != "message1" {
			t.Errorf("expected 'message1', got '%v'", event.Data)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for event")
	}

	// Cancel context
	cancel()
	time.Sleep(50 * time.Millisecond) // Wait for cleanup

	// Channel should be closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for channel close")
	}
}

func TestBus_NonBlockingPublish(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create subscriber with small buffer (16)
	ch := bus.Subscribe(ctx, "test.topic")

	// Fill the channel buffer
	for i := 0; i < 20; i++ {
		bus.Publish("test.topic", i)
	}

	// Publish should not block even with full channel
	// This should complete quickly
	done := make(chan bool)
	go func() {
		bus.Publish("test.topic", "extra")
		done <- true
	}()

	select {
	case <-done:
		// Success - publish didn't block
	case <-time.After(100 * time.Millisecond):
		t.Fatal("publish blocked with full channel")
	}

	// Drain some events
	receivedCount := 0
	for i := 0; i < 16; i++ {
		select {
		case <-ch:
			receivedCount++
		default:
			break
		}
	}

	if receivedCount == 0 {
		t.Error("expected to receive some events")
	}
}

func TestBus_ConcurrentPublishSubscribe(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const numPublishers = 5
	const numSubscribers = 5
	const messagesPerPublisher = 10

	// Start subscribers
	subscriberChans := make([]<-chan Event, numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		subscriberChans[i] = bus.Subscribe(ctx, "concurrent.topic")
	}

	// Start publishers
	done := make(chan bool)
	for i := 0; i < numPublishers; i++ {
		go func(id int) {
			for j := 0; j < messagesPerPublisher; j++ {
				bus.Publish("concurrent.topic", j)
			}
			done <- true
		}(i)
	}

	// Wait for all publishers
	for i := 0; i < numPublishers; i++ {
		<-done
	}

	// Each subscriber should receive messages
	for i, ch := range subscriberChans {
		receivedCount := 0
		timeout := time.After(1 * time.Second)
		for receivedCount < messagesPerPublisher*numPublishers {
			select {
			case <-ch:
				receivedCount++
			case <-timeout:
				// Some messages might be dropped due to buffer limits
				if receivedCount == 0 {
					t.Errorf("subscriber %d received no messages", i)
				}
				goto nextSubscriber
			}
		}
	nextSubscriber:
	}
}

func TestBus_DifferentTopics(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch1 := bus.Subscribe(ctx, "topic1")
	ch2 := bus.Subscribe(ctx, "topic2")

	bus.Publish("topic1", "message1")
	bus.Publish("topic2", "message2")

	// ch1 should only receive topic1 event
	select {
	case event := <-ch1:
		if event.Topic != "topic1" {
			t.Errorf("ch1 expected topic 'topic1', got '%s'", event.Topic)
		}
		if event.Data != "message1" {
			t.Errorf("ch1 expected data 'message1', got '%v'", event.Data)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for topic1 event on ch1")
	}

	// ch2 should only receive topic2 event
	select {
	case event := <-ch2:
		if event.Topic != "topic2" {
			t.Errorf("ch2 expected topic 'topic2', got '%s'", event.Topic)
		}
		if event.Data != "message2" {
			t.Errorf("ch2 expected data 'message2', got '%v'", event.Data)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for topic2 event on ch2")
	}

	// Channels should not have any more events
	select {
	case event := <-ch1:
		t.Errorf("ch1 received unexpected event: %v", event)
	case <-time.After(50 * time.Millisecond):
		// Expected - no more events
	}

	select {
	case event := <-ch2:
		t.Errorf("ch2 received unexpected event: %v", event)
	case <-time.After(50 * time.Millisecond):
		// Expected - no more events
	}
}
