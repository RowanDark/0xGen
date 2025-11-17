import { createFileRoute } from '@tanstack/react-router';
import { useCallback, useEffect, useState } from 'react';
import {
  Download,
  Upload,
  Sparkles,
  Plus,
  Trash2,
  Save,
  FolderOpen,
  Share2,
  Play,
  ArrowRight,
  Settings,
  X,
  GripVertical,
  Copy,
  Check
} from 'lucide-react';
import { motion, AnimatePresence, Reorder } from 'framer-motion';
import { Button } from '../components/ui/button';
import { cn } from '../lib/utils';
import { toast } from 'sonner';
import {
  cipherExecute,
  cipherPipeline,
  cipherDetect,
  cipherSmartDecode,
  cipherListOperations,
  cipherSaveRecipe,
  cipherListRecipes,
  cipherLoadRecipe,
  cipherDeleteRecipe,
  type CipherOperationInfo,
  type CipherPipelineOp,
  type CipherRecipe,
  type CipherDetection
} from '../lib/ipc';

export const Route = createFileRoute('/cipher')({
  component: CipherScreen
});

// Types
type PipelineBlock = {
  id: string;
  operation: string;
  config?: Record<string, unknown>;
};

type SmartSuggestion = {
  operation: string;
  confidence: number;
  reason: string;
};

function CipherScreen() {
  // State
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [pipeline, setPipeline] = useState<PipelineBlock[]>([]);
  const [operations, setOperations] = useState<CipherOperationInfo[]>([]);
  const [recipes, setRecipes] = useState<CipherRecipe[]>([]);
  const [detections, setDetections] = useState<CipherDetection[]>([]);
  const [smartMode, setSmartMode] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [showRecipeLibrary, setShowRecipeLibrary] = useState(false);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [showOperations, setShowOperations] = useState(false);
  const [copied, setCopied] = useState(false);

  // Recipe save form
  const [recipeName, setRecipeName] = useState('');
  const [recipeDescription, setRecipeDescription] = useState('');
  const [recipeTags, setRecipeTags] = useState('');

  // Load operations on mount
  useEffect(() => {
    loadOperations();
    loadRecipes();
  }, []);

  const loadOperations = async () => {
    try {
      const ops = await cipherListOperations();
      setOperations(ops);
    } catch (error) {
      toast.error('Failed to load operations: ' + String(error));
    }
  };

  const loadRecipes = async () => {
    try {
      const r = await cipherListRecipes();
      setRecipes(r);
    } catch (error) {
      console.error('Failed to load recipes:', error);
    }
  };

  // Auto-detect when input changes
  useEffect(() => {
    if (input && smartMode) {
      detectEncoding();
    }
  }, [input, smartMode]);

  const detectEncoding = async () => {
    if (!input.trim()) {
      setDetections([]);
      return;
    }

    try {
      const result = await cipherDetect(input);
      setDetections(result.detections);
    } catch (error) {
      console.error('Detection failed:', error);
    }
  };

  const executePipeline = async () => {
    if (!input.trim()) {
      toast.error('Please enter some input text');
      return;
    }

    if (pipeline.length === 0) {
      toast.error('Please add at least one operation to the pipeline');
      return;
    }

    setIsExecuting(true);
    try {
      const ops: CipherPipelineOp[] = pipeline.map((block) => ({
        name: block.operation,
        config: block.config
      }));

      const result = await cipherPipeline(input, ops);

      if (result.error) {
        toast.error(result.error);
        setOutput('');
      } else {
        setOutput(result.output || '');
        toast.success('Pipeline executed successfully');
      }
    } catch (error) {
      toast.error('Pipeline execution failed: ' + String(error));
    } finally {
      setIsExecuting(false);
    }
  };

  const executeSmartDecode = async () => {
    if (!input.trim()) {
      toast.error('Please enter some input text');
      return;
    }

    setIsExecuting(true);
    try {
      const result = await cipherSmartDecode(input);

      if (result.error) {
        toast.error(result.error);
      } else {
        setOutput(result.output || '');

        // Build pipeline from detected operations
        const blocks: PipelineBlock[] = result.pipeline.map((op, idx) => ({
          id: `block-${Date.now()}-${idx}`,
          operation: op
        }));
        setPipeline(blocks);

        toast.success(`Auto-decoded with ${result.confidence.toFixed(0)}% confidence`);
      }
    } catch (error) {
      toast.error('Smart decode failed: ' + String(error));
    } finally {
      setIsExecuting(false);
    }
  };

  const addOperation = (opName: string) => {
    const newBlock: PipelineBlock = {
      id: `block-${Date.now()}`,
      operation: opName
    };
    setPipeline([...pipeline, newBlock]);
    setShowOperations(false);
  };

  const removeOperation = (id: string) => {
    setPipeline(pipeline.filter((block) => block.id !== id));
  };

  const clearPipeline = () => {
    setPipeline([]);
    setOutput('');
  };

  const saveRecipe = async () => {
    if (!recipeName.trim()) {
      toast.error('Please enter a recipe name');
      return;
    }

    if (pipeline.length === 0) {
      toast.error('Please add at least one operation');
      return;
    }

    try {
      const ops: CipherPipelineOp[] = pipeline.map((block) => ({
        name: block.operation,
        config: block.config
      }));

      const tags = recipeTags.split(',').map((t) => t.trim()).filter((t) => t);

      await cipherSaveRecipe(recipeName, recipeDescription, tags, ops);
      toast.success('Recipe saved successfully');

      setShowSaveDialog(false);
      setRecipeName('');
      setRecipeDescription('');
      setRecipeTags('');

      loadRecipes();
    } catch (error) {
      toast.error('Failed to save recipe: ' + String(error));
    }
  };

  const loadRecipe = async (recipe: CipherRecipe) => {
    const blocks: PipelineBlock[] = recipe.pipeline.operations.map((op, idx) => ({
      id: `block-${Date.now()}-${idx}`,
      operation: op.name,
      config: op.config as Record<string, unknown> | undefined
    }));

    setPipeline(blocks);
    setShowRecipeLibrary(false);
    toast.success(`Loaded recipe: ${recipe.name}`);
  };

  const deleteRecipe = async (name: string) => {
    try {
      await cipherDeleteRecipe(name);
      toast.success('Recipe deleted');
      loadRecipes();
    } catch (error) {
      toast.error('Failed to delete recipe: ' + String(error));
    }
  };

  const exportRecipe = (recipe: CipherRecipe) => {
    const json = JSON.stringify(recipe, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${recipe.name}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Recipe exported');
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast.success('Copied to clipboard');
    }
  };

  // Group operations by type
  const operationsByType = operations.reduce((acc, op) => {
    const type = op.type || 'other';
    if (!acc[type]) acc[type] = [];
    acc[type].push(op);
    return acc;
  }, {} as Record<string, CipherOperationInfo[]>);

  return (
    <div className="flex flex-col h-screen bg-background">
      {/* Header */}
      <div className="border-b bg-card/50 backdrop-blur-sm">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Cipher</h1>
              <p className="text-sm text-muted-foreground mt-1">
                Smart encoder/decoder with visual transformation pipeline
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant={smartMode ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSmartMode(!smartMode)}
                className="gap-2"
              >
                <Sparkles className="h-4 w-4" />
                Smart Mode
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowRecipeLibrary(true)}
                className="gap-2"
              >
                <FolderOpen className="h-4 w-4" />
                Recipes
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowSaveDialog(true)}
                disabled={pipeline.length === 0}
                className="gap-2"
              >
                <Save className="h-4 w-4" />
                Save
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Input/Output */}
        <div className="grid grid-cols-2 gap-4 p-6 h-64 min-h-[16rem]">
          {/* Input */}
          <div className="flex flex-col">
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm font-medium">Input</label>
              {detections.length > 0 && smartMode && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>Detected:</span>
                  {detections.slice(0, 3).map((d) => (
                    <span
                      key={d.encoding}
                      className="px-2 py-0.5 bg-primary/10 text-primary rounded"
                    >
                      {d.encoding} ({(d.confidence * 100).toFixed(0)}%)
                    </span>
                  ))}
                </div>
              )}
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter text to encode/decode..."
              className="flex-1 w-full px-3 py-2 text-sm bg-background border rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-primary font-mono"
            />
          </div>

          {/* Output */}
          <div className="flex flex-col">
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm font-medium">Output</label>
              <Button
                variant="ghost"
                size="sm"
                onClick={copyOutput}
                disabled={!output}
                className="h-7 gap-2"
              >
                {copied ? (
                  <>
                    <Check className="h-3 w-3" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" />
                    Copy
                  </>
                )}
              </Button>
            </div>
            <textarea
              value={output}
              readOnly
              placeholder="Output will appear here..."
              className="flex-1 w-full px-3 py-2 text-sm bg-muted/50 border rounded-md resize-none focus:outline-none font-mono"
            />
          </div>
        </div>

        {/* Pipeline */}
        <div className="flex-1 flex flex-col px-6 pb-6 overflow-hidden">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">Transformation Pipeline</h2>
            <div className="flex items-center gap-2">
              {smartMode && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={executeSmartDecode}
                  disabled={isExecuting || !input}
                  className="gap-2"
                >
                  <Sparkles className="h-4 w-4" />
                  Auto-Decode
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowOperations(true)}
                className="gap-2"
              >
                <Plus className="h-4 w-4" />
                Add Operation
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={clearPipeline}
                disabled={pipeline.length === 0}
                className="gap-2"
              >
                <Trash2 className="h-4 w-4" />
                Clear
              </Button>
              <Button
                size="sm"
                onClick={executePipeline}
                disabled={isExecuting || pipeline.length === 0 || !input}
                className="gap-2"
              >
                <Play className="h-4 w-4" />
                Execute
              </Button>
            </div>
          </div>

          {/* Pipeline Visualization */}
          <div className="flex-1 overflow-auto border rounded-lg bg-card/50 p-4">
            {pipeline.length === 0 ? (
              <div className="h-full flex items-center justify-center text-muted-foreground">
                <div className="text-center">
                  <p className="text-sm mb-2">No operations in pipeline</p>
                  <p className="text-xs">Add operations to build your transformation chain</p>
                </div>
              </div>
            ) : (
              <Reorder.Group
                axis="y"
                values={pipeline}
                onReorder={setPipeline}
                className="space-y-2"
              >
                {pipeline.map((block, idx) => (
                  <Reorder.Item key={block.id} value={block}>
                    <motion.div
                      layout
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="flex items-center gap-3 p-3 bg-background border rounded-lg group hover:border-primary/50 transition-colors"
                    >
                      <GripVertical className="h-5 w-5 text-muted-foreground cursor-grab active:cursor-grabbing" />

                      <div className="flex items-center gap-2 flex-1">
                        <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/10 text-primary text-xs font-semibold">
                          {idx + 1}
                        </span>
                        <span className="text-sm font-medium">{block.operation}</span>
                      </div>

                      {idx < pipeline.length - 1 && (
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                      )}

                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeOperation(block.id)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </motion.div>
                  </Reorder.Item>
                ))}
              </Reorder.Group>
            )}
          </div>
        </div>
      </div>

      {/* Operations Dialog */}
      <AnimatePresence>
        {showOperations && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowOperations(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-card border rounded-lg shadow-lg max-w-2xl w-full max-h-[80vh] overflow-hidden flex flex-col"
            >
              <div className="px-6 py-4 border-b flex items-center justify-between">
                <h2 className="text-lg font-semibold">Add Operation</h2>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowOperations(false)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>

              <div className="flex-1 overflow-auto p-6">
                {Object.entries(operationsByType).map(([type, ops]) => (
                  <div key={type} className="mb-6 last:mb-0">
                    <h3 className="text-sm font-semibold mb-3 capitalize">{type}</h3>
                    <div className="grid grid-cols-2 gap-2">
                      {ops.map((op) => (
                        <button
                          key={op.name}
                          onClick={() => addOperation(op.name)}
                          className="px-4 py-3 text-left border rounded-lg hover:border-primary hover:bg-primary/5 transition-colors group"
                        >
                          <div className="font-medium text-sm">{op.name}</div>
                          {op.description && (
                            <div className="text-xs text-muted-foreground mt-1">
                              {op.description}
                            </div>
                          )}
                          {op.reversible && (
                            <div className="text-xs text-green-600 dark:text-green-400 mt-1">
                              Reversible
                            </div>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Recipe Library Dialog */}
      <AnimatePresence>
        {showRecipeLibrary && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowRecipeLibrary(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-card border rounded-lg shadow-lg max-w-2xl w-full max-h-[80vh] overflow-hidden flex flex-col"
            >
              <div className="px-6 py-4 border-b flex items-center justify-between">
                <h2 className="text-lg font-semibold">Recipe Library</h2>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowRecipeLibrary(false)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>

              <div className="flex-1 overflow-auto p-6">
                {recipes.length === 0 ? (
                  <div className="text-center text-muted-foreground py-8">
                    <p>No recipes saved yet</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {recipes.map((recipe) => (
                      <div
                        key={recipe.name}
                        className="p-4 border rounded-lg hover:border-primary/50 transition-colors"
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <h3 className="font-semibold">{recipe.name}</h3>
                            <p className="text-sm text-muted-foreground mt-1">
                              {recipe.description}
                            </p>
                            {recipe.tags.length > 0 && (
                              <div className="flex items-center gap-2 mt-2">
                                {recipe.tags.map((tag) => (
                                  <span
                                    key={tag}
                                    className="px-2 py-0.5 text-xs bg-primary/10 text-primary rounded"
                                  >
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => loadRecipe(recipe)}
                            >
                              <Upload className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => exportRecipe(recipe)}
                            >
                              <Share2 className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => deleteRecipe(recipe.name)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {recipe.pipeline.operations.length} operations
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Save Recipe Dialog */}
      <AnimatePresence>
        {showSaveDialog && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowSaveDialog(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-card border rounded-lg shadow-lg max-w-md w-full"
            >
              <div className="px-6 py-4 border-b flex items-center justify-between">
                <h2 className="text-lg font-semibold">Save Recipe</h2>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowSaveDialog(false)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>

              <div className="p-6 space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Name</label>
                  <input
                    type="text"
                    value={recipeName}
                    onChange={(e) => setRecipeName(e.target.value)}
                    placeholder="e.g., Double Base64"
                    className="w-full px-3 py-2 text-sm bg-background border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>

                <div>
                  <label className="text-sm font-medium mb-2 block">Description</label>
                  <textarea
                    value={recipeDescription}
                    onChange={(e) => setRecipeDescription(e.target.value)}
                    placeholder="Describe what this recipe does..."
                    className="w-full px-3 py-2 text-sm bg-background border rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-primary"
                    rows={3}
                  />
                </div>

                <div>
                  <label className="text-sm font-medium mb-2 block">Tags (comma-separated)</label>
                  <input
                    type="text"
                    value={recipeTags}
                    onChange={(e) => setRecipeTags(e.target.value)}
                    placeholder="e.g., encoding, obfuscation"
                    className="w-full px-3 py-2 text-sm bg-background border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-4">
                  <Button
                    variant="outline"
                    onClick={() => setShowSaveDialog(false)}
                  >
                    Cancel
                  </Button>
                  <Button onClick={saveRecipe}>
                    <Save className="h-4 w-4 mr-2" />
                    Save Recipe
                  </Button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
