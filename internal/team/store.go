package team

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/RowanDark/0xgen/internal/logging"
)

// Role represents a workspace-scoped permission level.
type Role string

const (
	// RoleAdmin has full control over a workspace.
	RoleAdmin Role = "admin"
	// RoleAnalyst can run scans and share cases.
	RoleAnalyst Role = "analyst"
	// RoleViewer has read-only access to workspace assets.
	RoleViewer Role = "viewer"
)

// ParseRole normalises the provided string into a Role value.
func ParseRole(input string) (Role, error) {
	switch Role(normalise(input)) {
	case RoleAdmin:
		return RoleAdmin, nil
	case RoleAnalyst:
		return RoleAnalyst, nil
	case RoleViewer:
		return RoleViewer, nil
	default:
		return "", fmt.Errorf("unknown role %q", input)
	}
}

func normalise(v string) string {
	b := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		ch := v[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch == ' ' || ch == '\n' || ch == '\t' {
			continue
		}
		b = append(b, ch)
	}
	return string(b)
}

// allows reports whether the caller role satisfies the required role.
func (r Role) allows(required Role) bool {
	return roleRank(r) >= roleRank(required)
}

func roleRank(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleAnalyst:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// Member captures workspace membership metadata.
type Member struct {
	UserID   string
	Role     Role
	JoinedAt time.Time
}

// Workspace tracks memberships and per-case access state.
type Workspace struct {
	ID        string
	Name      string
	CreatedAt time.Time
	Members   map[string]Member
	Cases     map[string]map[string]Role
}

// Invite represents a pending workspace membership grant.
type Invite struct {
	Token       string
	WorkspaceID string
	Role        Role
	CreatedBy   string
	ExpiresAt   time.Time
}

// CaseInvite grants case-scoped access to a workspace.
type CaseInvite struct {
	Token       string
	WorkspaceID string
	CaseID      string
	Role        Role
	CreatedBy   string
	ExpiresAt   time.Time
}

// CaseGrant captures the result of a case-share invite redemption.
type CaseGrant struct {
	WorkspaceID string
	CaseID      string
	Role        Role
	UserID      string
}

// Store persists workspace state in-memory and emits audit events.
type Store struct {
	mu        sync.RWMutex
	logger    *logging.AuditLogger
	workspace map[string]*Workspace
	invites   map[string]Invite
	caseInv   map[string]CaseInvite
}

// NewStore constructs a workspace store.
func NewStore(logger *logging.AuditLogger) *Store {
	return &Store{
		logger:    logger,
		workspace: make(map[string]*Workspace),
		invites:   make(map[string]Invite),
		caseInv:   make(map[string]CaseInvite),
	}
}

// CreateWorkspace registers a new workspace owned by the provided user.
func (s *Store) CreateWorkspace(name, ownerID string) (*Workspace, error) {
	name = strings.TrimSpace(name)
	ownerID = strings.TrimSpace(ownerID)
	if name == "" {
		return nil, errors.New("workspace name is required")
	}
	if ownerID == "" {
		return nil, errors.New("owner id is required")
	}
	ws := &Workspace{
		ID:        uuid.NewString(),
		Name:      name,
		CreatedAt: time.Now().UTC(),
		Members:   map[string]Member{},
		Cases:     map[string]map[string]Role{},
	}
	ws.Members[ownerID] = Member{UserID: ownerID, Role: RoleAdmin, JoinedAt: ws.CreatedAt}
	s.mu.Lock()
	s.workspace[ws.ID] = ws
	s.mu.Unlock()
	s.emit(logging.EventWorkspaceLifecycle, logging.DecisionAllow, map[string]any{
		"workspace_id": ws.ID,
		"name":         ws.Name,
		"actor_id":     ownerID,
		"action":       "create",
	})
	return cloneWorkspace(ws), nil
}

// AddMember grants membership to a workspace.
func (s *Store) AddMember(workspaceID, actorID, userID string, role Role) error {
	workspaceID = strings.TrimSpace(workspaceID)
	actorID = strings.TrimSpace(actorID)
	userID = strings.TrimSpace(userID)
	if workspaceID == "" || actorID == "" || userID == "" {
		return errors.New("workspace id, actor id, and user id are required")
	}
	if roleRank(role) == 0 {
		return fmt.Errorf("invalid role %q", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspace[workspaceID]
	if !ok {
		return errors.New("workspace not found")
	}
	actor, ok := ws.Members[actorID]
	if !ok || !actor.Role.allows(RoleAdmin) {
		return errors.New("actor lacks permission")
	}
	current, exists := ws.Members[userID]
	now := time.Now().UTC()
	if !exists || roleRank(role) > roleRank(current.Role) {
		ws.Members[userID] = Member{UserID: userID, Role: role, JoinedAt: chooseTime(current.JoinedAt, now)}
	}
	s.emit(logging.EventWorkspaceMembership, logging.DecisionAllow, map[string]any{
		"workspace_id": workspaceID,
		"actor_id":     actorID,
		"target_id":    userID,
		"role":         string(role),
		"action":       "add_member",
	})
	return nil
}

// UpdateRole elevates or demotes a workspace member.
func (s *Store) UpdateRole(workspaceID, actorID, userID string, role Role) error {
	workspaceID = strings.TrimSpace(workspaceID)
	actorID = strings.TrimSpace(actorID)
	userID = strings.TrimSpace(userID)
	if workspaceID == "" || actorID == "" || userID == "" {
		return errors.New("workspace id, actor id, and user id are required")
	}
	if roleRank(role) == 0 {
		return fmt.Errorf("invalid role %q", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspace[workspaceID]
	if !ok {
		return errors.New("workspace not found")
	}
	actor, ok := ws.Members[actorID]
	if !ok || !actor.Role.allows(RoleAdmin) {
		return errors.New("actor lacks permission")
	}
	member, ok := ws.Members[userID]
	if !ok {
		return errors.New("member not found")
	}
	member.Role = role
	ws.Members[userID] = member
	s.emit(logging.EventWorkspaceMembership, logging.DecisionAllow, map[string]any{
		"workspace_id": workspaceID,
		"actor_id":     actorID,
		"target_id":    userID,
		"role":         string(role),
		"action":       "update_role",
	})
	return nil
}

// RemoveMember revokes workspace membership.
func (s *Store) RemoveMember(workspaceID, actorID, userID string) error {
	workspaceID = strings.TrimSpace(workspaceID)
	actorID = strings.TrimSpace(actorID)
	userID = strings.TrimSpace(userID)
	if workspaceID == "" || actorID == "" || userID == "" {
		return errors.New("workspace id, actor id, and user id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspace[workspaceID]
	if !ok {
		return errors.New("workspace not found")
	}
	actor, ok := ws.Members[actorID]
	if !ok || !actor.Role.allows(RoleAdmin) {
		return errors.New("actor lacks permission")
	}
	delete(ws.Members, userID)
	for caseID := range ws.Cases {
		delete(ws.Cases[caseID], userID)
	}
	s.emit(logging.EventWorkspaceMembership, logging.DecisionAllow, map[string]any{
		"workspace_id": workspaceID,
		"actor_id":     actorID,
		"target_id":    userID,
		"action":       "remove_member",
	})
	return nil
}

// Authorize reports whether the user has at least the required role.
func (s *Store) Authorize(workspaceID, userID string, required Role) bool {
	workspaceID = strings.TrimSpace(workspaceID)
	userID = strings.TrimSpace(userID)
	if workspaceID == "" || userID == "" {
		return false
	}
	s.mu.RLock()
	ws, ok := s.workspace[workspaceID]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	member, ok := ws.Members[userID]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	return member.Role.allows(required)
}

// GenerateInvite produces a workspace membership invite token.
func (s *Store) GenerateInvite(workspaceID, actorID string, role Role, ttl time.Duration) (string, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	actorID = strings.TrimSpace(actorID)
	if workspaceID == "" || actorID == "" {
		return "", errors.New("workspace id and actor id are required")
	}
	if roleRank(role) == 0 {
		return "", fmt.Errorf("invalid role %q", role)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	expires := time.Now().UTC().Add(ttl)
	token := uuid.NewString()
	invite := Invite{Token: token, WorkspaceID: workspaceID, Role: role, CreatedBy: actorID, ExpiresAt: expires}
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspace[workspaceID]
	if !ok {
		return "", errors.New("workspace not found")
	}
	if actor, ok := ws.Members[actorID]; !ok || !actor.Role.allows(RoleAnalyst) {
		return "", errors.New("actor lacks permission")
	}
	s.invites[token] = invite
	s.emit(logging.EventWorkspaceInvite, logging.DecisionAllow, map[string]any{
		"workspace_id": workspaceID,
		"actor_id":     actorID,
		"role":         string(role),
		"expires_at":   invite.ExpiresAt,
	})
	return token, nil
}

// ConsumeInvite redeems a workspace invite and adds the member.
func (s *Store) ConsumeInvite(token, userID string) (*Workspace, Role, error) {
	token = strings.TrimSpace(token)
	userID = strings.TrimSpace(userID)
	if token == "" || userID == "" {
		return nil, "", errors.New("token and user id are required")
	}
	s.mu.Lock()
	invite, ok := s.invites[token]
	if !ok {
		s.mu.Unlock()
		return nil, "", errors.New("invite not found")
	}
	if time.Now().UTC().After(invite.ExpiresAt) {
		delete(s.invites, token)
		s.mu.Unlock()
		return nil, "", errors.New("invite expired")
	}
	ws, ok := s.workspace[invite.WorkspaceID]
	if !ok {
		delete(s.invites, token)
		s.mu.Unlock()
		return nil, "", errors.New("workspace not found")
	}
	existing, ok := ws.Members[userID]
	now := time.Now().UTC()
	if !ok || roleRank(invite.Role) > roleRank(existing.Role) {
		ws.Members[userID] = Member{UserID: userID, Role: invite.Role, JoinedAt: chooseTime(existing.JoinedAt, now)}
	}
	delete(s.invites, token)
	wsCopy := cloneWorkspace(ws)
	s.mu.Unlock()
	s.emit(logging.EventWorkspaceInvite, logging.DecisionAllow, map[string]any{
		"workspace_id": invite.WorkspaceID,
		"target_id":    userID,
		"role":         string(invite.Role),
		"action":       "accept",
	})
	return wsCopy, invite.Role, nil
}

// GenerateCaseInvite produces an invite token tied to a case identifier.
func (s *Store) GenerateCaseInvite(workspaceID, actorID, caseID string, role Role, ttl time.Duration) (string, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	actorID = strings.TrimSpace(actorID)
	caseID = strings.TrimSpace(caseID)
	if workspaceID == "" || actorID == "" || caseID == "" {
		return "", errors.New("workspace id, actor id, and case id are required")
	}
	if roleRank(role) == 0 {
		return "", fmt.Errorf("invalid role %q", role)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	token := uuid.NewString()
	expires := time.Now().UTC().Add(ttl)
	invite := CaseInvite{Token: token, WorkspaceID: workspaceID, CaseID: caseID, Role: role, CreatedBy: actorID, ExpiresAt: expires}
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspace[workspaceID]
	if !ok {
		return "", errors.New("workspace not found")
	}
	actor, ok := ws.Members[actorID]
	if !ok || !actor.Role.allows(RoleAnalyst) {
		return "", errors.New("actor lacks permission")
	}
	s.caseInv[token] = invite
	s.emit(logging.EventCaseShare, logging.DecisionAllow, map[string]any{
		"workspace_id": workspaceID,
		"actor_id":     actorID,
		"case_id":      caseID,
		"role":         string(role),
		"expires_at":   invite.ExpiresAt,
	})
	return token, nil
}

// ConsumeCaseInvite redeems a case invite and registers access for the user.
func (s *Store) ConsumeCaseInvite(token, userID string) (CaseGrant, error) {
	token = strings.TrimSpace(token)
	userID = strings.TrimSpace(userID)
	if token == "" || userID == "" {
		return CaseGrant{}, errors.New("token and user id are required")
	}
	s.mu.Lock()
	invite, ok := s.caseInv[token]
	if !ok {
		s.mu.Unlock()
		return CaseGrant{}, errors.New("case invite not found")
	}
	if time.Now().UTC().After(invite.ExpiresAt) {
		delete(s.caseInv, token)
		s.mu.Unlock()
		return CaseGrant{}, errors.New("case invite expired")
	}
	ws, ok := s.workspace[invite.WorkspaceID]
	if !ok {
		delete(s.caseInv, token)
		s.mu.Unlock()
		return CaseGrant{}, errors.New("workspace not found")
	}
	// Ensure membership exists with at least the invited role.
	member, exists := ws.Members[userID]
	if !exists || roleRank(invite.Role) > roleRank(member.Role) {
		now := time.Now().UTC()
		ws.Members[userID] = Member{UserID: userID, Role: invite.Role, JoinedAt: chooseTime(member.JoinedAt, now)}
	}
	grants, ok := ws.Cases[invite.CaseID]
	if !ok {
		grants = make(map[string]Role)
		ws.Cases[invite.CaseID] = grants
	}
	current := grants[userID]
	if roleRank(invite.Role) > roleRank(current) {
		grants[userID] = invite.Role
	}
	delete(s.caseInv, token)
	s.mu.Unlock()
	grant := CaseGrant{WorkspaceID: invite.WorkspaceID, CaseID: invite.CaseID, Role: invite.Role, UserID: userID}
	s.emit(logging.EventCaseShare, logging.DecisionAllow, map[string]any{
		"workspace_id": invite.WorkspaceID,
		"case_id":      invite.CaseID,
		"target_id":    userID,
		"role":         string(invite.Role),
		"action":       "accept",
	})
	return grant, nil
}

// HasCaseAccess reports whether the user can view the shared case.
func (s *Store) HasCaseAccess(workspaceID, userID, caseID string, required Role) bool {
	workspaceID = strings.TrimSpace(workspaceID)
	userID = strings.TrimSpace(userID)
	caseID = strings.TrimSpace(caseID)
	if workspaceID == "" || userID == "" || caseID == "" {
		return false
	}
	s.mu.RLock()
	ws, ok := s.workspace[workspaceID]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	grants := ws.Cases[caseID]
	member := ws.Members[userID]
	s.mu.RUnlock()
	caseRole := grants[userID]
	if roleRank(caseRole) == 0 {
		if roleRank(member.Role) == 0 {
			return false
		}
		if !member.Role.allows(RoleAnalyst) {
			return false
		}
		return member.Role.allows(required)
	}
	return caseRole.allows(required)
}

// WorkspaceSnapshot returns a copy of the workspace state.
func (s *Store) WorkspaceSnapshot(workspaceID string) (*Workspace, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, errors.New("workspace id is required")
	}
	s.mu.RLock()
	ws, ok := s.workspace[workspaceID]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("workspace not found")
	}
	return cloneWorkspace(ws), nil
}

func chooseTime(existing, fallback time.Time) time.Time {
	if !existing.IsZero() {
		return existing
	}
	return fallback
}

func cloneWorkspace(ws *Workspace) *Workspace {
	if ws == nil {
		return nil
	}
	copy := &Workspace{
		ID:        ws.ID,
		Name:      ws.Name,
		CreatedAt: ws.CreatedAt,
		Members:   make(map[string]Member, len(ws.Members)),
		Cases:     make(map[string]map[string]Role, len(ws.Cases)),
	}
	for id, member := range ws.Members {
		copy.Members[id] = member
	}
	for caseID, grants := range ws.Cases {
		inner := make(map[string]Role, len(grants))
		for uid, role := range grants {
			inner[uid] = role
		}
		copy.Cases[caseID] = inner
	}
	return copy
}

func (s *Store) emit(event logging.EventType, decision logging.Decision, metadata map[string]any) {
	if s.logger == nil {
		return
	}
	_ = s.logger.Emit(logging.AuditEvent{
		EventType: event,
		Decision:  decision,
		Metadata:  metadata,
	})
}
