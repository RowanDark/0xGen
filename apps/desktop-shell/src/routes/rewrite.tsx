import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import {
  Plus,
  Trash2,
  Play,
  Save,
  Download,
  Upload,
  Copy,
  Edit2,
  AlertCircle,
  CheckCircle,
  Clock,
  TrendingUp
} from 'lucide-react';
import {
  listRewriteRules,
  createRewriteRule,
  updateRewriteRule,
  deleteRewriteRule,
  importRewriteRules,
  exportRewriteRules,
  testRewriteRequest,
  testRewriteResponse,
  listRewriteTestCases,
  runAllRewriteTestCases,
  fetchRewriteMetrics,
  type RewriteRule,
  type RewriteScope,
  type RewriteCondition,
  type RewriteAction,
  type RewriteTestRequestInput,
  type RewriteTestResponseInput,
  type RewriteSandboxResult,
  type RewriteTestCase,
  type RewriteTestResult,
  type RewriteMetrics
} from '@/lib/ipc';

export default function RewriteScreen() {
  const [rules, setRules] = useState<RewriteRule[]>([]);
  const [testCases, setTestCases] = useState<RewriteTestCase[]>([]);
  const [metrics, setMetrics] = useState<RewriteMetrics | null>(null);
  const [selectedRule, setSelectedRule] = useState<RewriteRule | null>(null);
  const [sandboxResult, setSandboxResult] = useState<RewriteSandboxResult | null>(null);
  const [testResults, setTestResults] = useState<RewriteTestResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('rules');

  // Rule editor state
  const [editingRule, setEditingRule] = useState<Partial<RewriteRule> | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  // Sandbox test state
  const [testInput, setTestInput] = useState<Partial<RewriteTestRequestInput>>({
    method: 'GET',
    url: 'https://example.com',
    headers: {},
    body: ''
  });
  const [testType, setTestType] = useState<'request' | 'response'>('request');

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const [rulesData, testCasesData, metricsData] = await Promise.all([
        listRewriteRules(),
        listRewriteTestCases(),
        fetchRewriteMetrics()
      ]);
      setRules(rulesData);
      setTestCases(testCasesData);
      setMetrics(metricsData);
    } catch (error) {
      console.error('Failed to load rewrite data:', error);
    }
  }

  async function handleCreateRule() {
    if (!editingRule) return;

    setLoading(true);
    try {
      const newRule: Omit<RewriteRule, 'id'> = {
        name: editingRule.name || 'New Rule',
        description: editingRule.description || '',
        enabled: editingRule.enabled ?? true,
        priority: editingRule.priority ?? 10,
        scope: editingRule.scope || {
          direction: 'request',
          methods: [],
          urlPattern: '.*'
        },
        conditions: editingRule.conditions || [],
        actions: editingRule.actions || []
      };

      await createRewriteRule(newRule);
      await loadData();
      setEditingRule(null);
      setIsCreating(false);
    } catch (error) {
      console.error('Failed to create rule:', error);
    } finally {
      setLoading(false);
    }
  }

  async function handleUpdateRule() {
    if (!editingRule || !editingRule.id) return;

    setLoading(true);
    try {
      const updatedRule: Omit<RewriteRule, 'id'> = {
        name: editingRule.name || 'Updated Rule',
        description: editingRule.description || '',
        enabled: editingRule.enabled ?? true,
        priority: editingRule.priority ?? 10,
        scope: editingRule.scope || {
          direction: 'request',
          methods: [],
          urlPattern: '.*'
        },
        conditions: editingRule.conditions || [],
        actions: editingRule.actions || []
      };

      await updateRewriteRule(editingRule.id, updatedRule);
      await loadData();
      setEditingRule(null);
    } catch (error) {
      console.error('Failed to update rule:', error);
    } finally {
      setLoading(false);
    }
  }

  async function handleDeleteRule(id: number) {
    if (!confirm('Are you sure you want to delete this rule?')) return;

    setLoading(true);
    try {
      await deleteRewriteRule(id);
      await loadData();
      if (selectedRule?.id === id) {
        setSelectedRule(null);
      }
    } catch (error) {
      console.error('Failed to delete rule:', error);
    } finally {
      setLoading(false);
    }
  }

  async function handleTestInSandbox() {
    setLoading(true);
    setSandboxResult(null);

    try {
      const ruleIds = selectedRule ? [selectedRule.id!] : [];

      if (testType === 'request') {
        const input: RewriteTestRequestInput = {
          method: testInput.method || 'GET',
          url: testInput.url || 'https://example.com',
          headers: testInput.headers || {},
          body: testInput.body || ''
        };
        const result = await testRewriteRequest(input, ruleIds);
        setSandboxResult(result);
      } else {
        const input: RewriteTestResponseInput = {
          statusCode: 200,
          headers: testInput.headers || {},
          body: testInput.body || ''
        };
        const result = await testRewriteResponse(input, ruleIds);
        setSandboxResult(result);
      }
    } catch (error) {
      console.error('Failed to test in sandbox:', error);
    } finally {
      setLoading(false);
    }
  }

  async function handleRunAllTests() {
    setLoading(true);
    try {
      const results = await runAllRewriteTestCases();
      setTestResults(results);
    } catch (error) {
      console.error('Failed to run test cases:', error);
    } finally {
      setLoading(false);
    }
  }

  async function handleExportRules() {
    try {
      const exportedRules = await exportRewriteRules();
      const blob = new Blob([JSON.stringify(exportedRules, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rewrite-rules-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export rules:', error);
    }
  }

  function startCreatingRule() {
    setEditingRule({
      name: '',
      description: '',
      enabled: true,
      priority: 10,
      scope: {
        direction: 'request',
        methods: [],
        urlPattern: '.*'
      },
      conditions: [],
      actions: []
    });
    setIsCreating(true);
  }

  function startEditingRule(rule: RewriteRule) {
    setEditingRule({ ...rule });
    setIsCreating(false);
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Rewrite Engine</h1>
          <p className="text-muted-foreground">
            Transform HTTP traffic with powerful match and rewrite rules
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={handleExportRules}>
            <Download className="mr-2 h-4 w-4" />
            Export Rules
          </Button>
          <Button onClick={startCreatingRule}>
            <Plus className="mr-2 h-4 w-4" />
            New Rule
          </Button>
        </div>
      </div>

      {/* Metrics Overview */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.totalRequests.toLocaleString()}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Responses</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.totalResponses.toLocaleString()}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Rules Applied</CardTitle>
              <CheckCircle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.rulesApplied.toLocaleString()}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Avg Latency</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.averageLatency.toFixed(2)}ms</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">Rules ({rules.length})</TabsTrigger>
          <TabsTrigger value="sandbox">Sandbox</TabsTrigger>
          <TabsTrigger value="tests">Test Cases ({testCases.length})</TabsTrigger>
        </TabsList>

        {/* Rules Tab */}
        <TabsContent value="rules" className="space-y-4">
          {editingRule ? (
            <Card>
              <CardHeader>
                <CardTitle>{isCreating ? 'Create New Rule' : 'Edit Rule'}</CardTitle>
                <CardDescription>
                  Configure rule properties, scope, conditions, and actions
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Basic Info */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">Rule Name</Label>
                    <Input
                      id="name"
                      value={editingRule.name || ''}
                      onChange={(e) => setEditingRule({ ...editingRule, name: e.target.value })}
                      placeholder="e.g., Add API Key Header"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="priority">Priority</Label>
                    <Input
                      id="priority"
                      type="number"
                      value={editingRule.priority || 10}
                      onChange={(e) => setEditingRule({ ...editingRule, priority: parseInt(e.target.value) })}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Textarea
                    id="description"
                    value={editingRule.description || ''}
                    onChange={(e) => setEditingRule({ ...editingRule, description: e.target.value })}
                    placeholder="Describe what this rule does..."
                  />
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    id="enabled"
                    checked={editingRule.enabled ?? true}
                    onCheckedChange={(checked) => setEditingRule({ ...editingRule, enabled: checked })}
                  />
                  <Label htmlFor="enabled">Enabled</Label>
                </div>

                {/* Scope */}
                <div className="space-y-2">
                  <Label>Scope</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="direction">Direction</Label>
                      <Select
                        value={editingRule.scope?.direction || 'request'}
                        onValueChange={(value) =>
                          setEditingRule({
                            ...editingRule,
                            scope: { ...editingRule.scope, direction: value } as RewriteScope
                          })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="request">Request</SelectItem>
                          <SelectItem value="response">Response</SelectItem>
                          <SelectItem value="both">Both</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="urlPattern">URL Pattern (regex)</Label>
                      <Input
                        id="urlPattern"
                        value={editingRule.scope?.urlPattern || '.*'}
                        onChange={(e) =>
                          setEditingRule({
                            ...editingRule,
                            scope: { ...editingRule.scope, urlPattern: e.target.value } as RewriteScope
                          })
                        }
                        placeholder=".*"
                      />
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex justify-end gap-2">
                  <Button
                    variant="outline"
                    onClick={() => {
                      setEditingRule(null);
                      setIsCreating(false);
                    }}
                  >
                    Cancel
                  </Button>
                  <Button onClick={isCreating ? handleCreateRule : handleUpdateRule} disabled={loading}>
                    <Save className="mr-2 h-4 w-4" />
                    {isCreating ? 'Create Rule' : 'Save Changes'}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {rules.length === 0 ? (
                <Card>
                  <CardContent className="flex flex-col items-center justify-center py-12">
                    <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
                    <p className="text-lg font-medium mb-2">No rules configured</p>
                    <p className="text-sm text-muted-foreground mb-4">
                      Create your first rule to start transforming HTTP traffic
                    </p>
                    <Button onClick={startCreatingRule}>
                      <Plus className="mr-2 h-4 w-4" />
                      Create Rule
                    </Button>
                  </CardContent>
                </Card>
              ) : (
                rules.map((rule) => (
                  <Card key={rule.id} className={selectedRule?.id === rule.id ? 'border-primary' : ''}>
                    <CardHeader>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <CardTitle>{rule.name}</CardTitle>
                            <Badge variant={rule.enabled ? 'default' : 'secondary'}>
                              {rule.enabled ? 'Enabled' : 'Disabled'}
                            </Badge>
                            <Badge variant="outline">Priority: {rule.priority}</Badge>
                            <Badge variant="outline">{rule.scope.direction}</Badge>
                          </div>
                          <CardDescription className="mt-1">{rule.description}</CardDescription>
                        </div>
                        <div className="flex gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => startEditingRule(rule)}
                          >
                            <Edit2 className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setSelectedRule(rule)}
                          >
                            <Play className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteRule(rule.id!)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2 text-sm">
                        <div>
                          <span className="font-medium">URL Pattern:</span> {rule.scope.urlPattern}
                        </div>
                        <div>
                          <span className="font-medium">Conditions:</span> {rule.conditions?.length || 0}
                        </div>
                        <div>
                          <span className="font-medium">Actions:</span> {rule.actions?.length || 0}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          )}
        </TabsContent>

        {/* Sandbox Tab */}
        <TabsContent value="sandbox" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Input Panel */}
            <Card>
              <CardHeader>
                <CardTitle>Test Input</CardTitle>
                <CardDescription>Configure the request/response to test</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Test Type</Label>
                  <Select value={testType} onValueChange={(v) => setTestType(v as 'request' | 'response')}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="request">Request</SelectItem>
                      <SelectItem value="response">Response</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {testType === 'request' && (
                  <>
                    <div className="space-y-2">
                      <Label htmlFor="method">Method</Label>
                      <Select
                        value={testInput.method || 'GET'}
                        onValueChange={(v) => setTestInput({ ...testInput, method: v })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="GET">GET</SelectItem>
                          <SelectItem value="POST">POST</SelectItem>
                          <SelectItem value="PUT">PUT</SelectItem>
                          <SelectItem value="DELETE">DELETE</SelectItem>
                          <SelectItem value="PATCH">PATCH</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="url">URL</Label>
                      <Input
                        id="url"
                        value={testInput.url || ''}
                        onChange={(e) => setTestInput({ ...testInput, url: e.target.value })}
                        placeholder="https://api.example.com/endpoint"
                      />
                    </div>
                  </>
                )}

                <div className="space-y-2">
                  <Label htmlFor="body">Body</Label>
                  <Textarea
                    id="body"
                    value={testInput.body || ''}
                    onChange={(e) => setTestInput({ ...testInput, body: e.target.value })}
                    placeholder="Request/response body..."
                    rows={6}
                  />
                </div>

                <Button onClick={handleTestInSandbox} disabled={loading} className="w-full">
                  <Play className="mr-2 h-4 w-4" />
                  Test in Sandbox
                </Button>
              </CardContent>
            </Card>

            {/* Output Panel */}
            <Card>
              <CardHeader>
                <CardTitle>Sandbox Result</CardTitle>
                <CardDescription>
                  {sandboxResult ? 'Rules applied successfully' : 'Run a test to see results'}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {sandboxResult ? (
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      {sandboxResult.success ? (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      ) : (
                        <AlertCircle className="h-5 w-5 text-red-500" />
                      )}
                      <span className="font-medium">
                        {sandboxResult.success ? 'Success' : 'Failed'}
                      </span>
                      <Badge variant="outline">{sandboxResult.duration.toFixed(2)}ms</Badge>
                    </div>

                    <div className="space-y-2">
                      <div className="text-sm">
                        <span className="font-medium">Rules Executed:</span>{' '}
                        {sandboxResult.executionLog.rulesExecuted}
                      </div>
                      <div className="text-sm">
                        <span className="font-medium">Rules Matched:</span>{' '}
                        {sandboxResult.executionLog.rulesMatched}
                      </div>
                      <div className="text-sm">
                        <span className="font-medium">Actions Applied:</span>{' '}
                        {sandboxResult.executionLog.actionsApplied}
                      </div>
                    </div>

                    {sandboxResult.warnings.length > 0 && (
                      <div className="space-y-2">
                        <Label>Warnings</Label>
                        {sandboxResult.warnings.map((warning, idx) => (
                          <div key={idx} className="text-sm text-amber-600 flex items-start gap-2">
                            <AlertCircle className="h-4 w-4 mt-0.5" />
                            <span>{warning.message}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {sandboxResult.diff.headerChanges.length > 0 && (
                      <div className="space-y-2">
                        <Label>Header Changes</Label>
                        <div className="space-y-1 text-sm">
                          {sandboxResult.diff.headerChanges.map((change, idx) => (
                            <div key={idx} className="flex items-center gap-2">
                              <Badge variant="outline" className="text-xs">
                                {change.action}
                              </Badge>
                              <span className="font-mono text-xs">{change.name}</span>
                              {change.action === 'modified' && (
                                <span className="text-muted-foreground text-xs">
                                  {change.oldValue} → {change.newValue}
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                    <Play className="h-12 w-12 mb-4" />
                    <p>No test results yet</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Test Cases Tab */}
        <TabsContent value="tests" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Test Cases</CardTitle>
                  <CardDescription>Saved test cases for regression testing</CardDescription>
                </div>
                <Button onClick={handleRunAllTests} disabled={loading}>
                  <Play className="mr-2 h-4 w-4" />
                  Run All Tests
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {testCases.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <AlertCircle className="h-12 w-12 mb-4" />
                  <p>No test cases yet</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {testCases.map((testCase) => (
                    <div key={testCase.id} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex-1">
                        <div className="font-medium">{testCase.name}</div>
                        <div className="text-sm text-muted-foreground">{testCase.description}</div>
                        <div className="flex gap-2 mt-1">
                          <Badge variant="outline">{testCase.type}</Badge>
                          {testCase.tags?.map((tag) => (
                            <Badge key={tag} variant="secondary" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm">
                          <Play className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {testResults.length > 0 && (
                <div className="mt-6 space-y-2">
                  <Label>Test Results</Label>
                  <div className="space-y-2">
                    {testResults.map((result) => (
                      <div
                        key={result.testCaseId}
                        className="flex items-center justify-between p-3 border rounded-lg"
                      >
                        <div className="flex items-center gap-3">
                          {result.passed ? (
                            <CheckCircle className="h-5 w-5 text-green-500" />
                          ) : (
                            <AlertCircle className="h-5 w-5 text-red-500" />
                          )}
                          <div>
                            <div className="font-medium">{result.testCaseName}</div>
                            {!result.passed && result.failures.length > 0 && (
                              <div className="text-sm text-red-600">{result.failures.join(', ')}</div>
                            )}
                          </div>
                        </div>
                        <Badge variant="outline">{result.duration.toFixed(2)}ms</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
