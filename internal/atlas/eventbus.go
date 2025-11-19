package atlas

import (
	"context"
	"sync"
	"time"
)

// Bus provides an in-process pub/sub system for scan events.
type Bus struct {
	mu    sync.RWMutex
	subs  map[string]map[int]chan Event
	next  int
	topic string
}

// NewBus returns a new, empty event bus.
func NewBus() *Bus {
	return &Bus{
		subs: make(map[string]map[int]chan Event),
	}
}

// Publish emits an event to all subscribers of the topic.
func (b *Bus) Publish(topic string, data interface{}) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	event := Event{
		Topic:     topic,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Publish to topic-specific subscribers
	if topicSubs, ok := b.subs[topic]; ok {
		for _, ch := range topicSubs {
			select {
			case ch <- event:
			default:
				// Channel full, skip (non-blocking)
			}
		}
	}

	// Publish to wildcard subscribers
	if wildcardSubs, ok := b.subs["*"]; ok {
		for _, ch := range wildcardSubs {
			select {
			case ch <- event:
			default:
				// Channel full, skip (non-blocking)
			}
		}
	}
}

// Subscribe registers a subscriber for events on the given topic.
// Use "*" to subscribe to all events.
// The returned channel is closed when the context is cancelled.
func (b *Bus) Subscribe(ctx context.Context, topic string) <-chan Event {
	ch := make(chan Event, 16)

	b.mu.Lock()
	if b.subs[topic] == nil {
		b.subs[topic] = make(map[int]chan Event)
	}
	id := b.next
	b.next++
	b.subs[topic][id] = ch
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if topicSubs, ok := b.subs[topic]; ok {
			if sub, ok := topicSubs[id]; ok {
				delete(topicSubs, id)
				close(sub)
			}
			if len(topicSubs) == 0 {
				delete(b.subs, topic)
			}
		}
		b.mu.Unlock()
	}()

	return ch
}

// SubscriberCount returns the number of subscribers for a topic.
func (b *Bus) SubscriberCount(topic string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if topicSubs, ok := b.subs[topic]; ok {
		return len(topicSubs)
	}
	return 0
}

// Topics returns all topics with active subscribers.
func (b *Bus) Topics() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	topics := make([]string, 0, len(b.subs))
	for topic := range b.subs {
		topics = append(topics, topic)
	}
	return topics
}
