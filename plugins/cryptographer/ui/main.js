(() => {
  const input = document.getElementById('input');
  const output = document.getElementById('output');
  const recipePanel = document.getElementById('recipe-panel');
  const operationsPanel = document.getElementById('operations-panel');
  const detectBtn = document.getElementById('detect-btn');
  const clearRecipeBtn = document.getElementById('clear-recipe-btn');
  const saveRecipeBtn = document.getElementById('save-recipe-btn');

  // Available operations (will be populated from backend)
  const operations = [
    { name: 'base64_encode', category: 'Encoding', description: 'Encode as Base64' },
    { name: 'base64_decode', category: 'Decoding', description: 'Decode Base64' },
    { name: 'base64url_encode', category: 'Encoding', description: 'Encode as URL-safe Base64' },
    { name: 'base64url_decode', category: 'Decoding', description: 'Decode URL-safe Base64' },
    { name: 'url_encode', category: 'Encoding', description: 'URL encode (percent encode)' },
    { name: 'url_decode', category: 'Decoding', description: 'URL decode' },
    { name: 'html_encode', category: 'Encoding', description: 'HTML entity encode' },
    { name: 'html_decode', category: 'Decoding', description: 'HTML entity decode' },
    { name: 'hex_encode', category: 'Encoding', description: 'Encode as hexadecimal' },
    { name: 'hex_decode', category: 'Decoding', description: 'Decode hexadecimal' },
    { name: 'binary_encode', category: 'Encoding', description: 'Encode as binary' },
    { name: 'binary_decode', category: 'Decoding', description: 'Decode binary' },
    { name: 'ascii_to_hex', category: 'Encoding', description: 'Convert ASCII to hex' },
    { name: 'hex_to_ascii', category: 'Decoding', description: 'Convert hex to ASCII' },
    { name: 'gzip_compress', category: 'Compression', description: 'Gzip compress' },
    { name: 'gzip_decompress', category: 'Compression', description: 'Gzip decompress' },
    { name: 'md5_hash', category: 'Hashing', description: 'MD5 hash' },
    { name: 'sha1_hash', category: 'Hashing', description: 'SHA-1 hash' },
    { name: 'sha256_hash', category: 'Hashing', description: 'SHA-256 hash' },
    { name: 'sha512_hash', category: 'Hashing', description: 'SHA-512 hash' },
    { name: 'jwt_decode', category: 'JWT', description: 'Decode JWT token' },
    { name: 'jwt_verify', category: 'JWT', description: 'Verify JWT token' },
    { name: 'jwt_sign', category: 'JWT', description: 'Sign JWT token' },
  ];

  // Current recipe (chain of operations)
  let recipe = [];

  // Initialize UI
  function init() {
    renderOperations();
    renderRecipe();
    setupEventListeners();
  }

  // Render available operations
  function renderOperations() {
    const categories = {};
    operations.forEach(op => {
      if (!categories[op.category]) {
        categories[op.category] = [];
      }
      categories[op.category].push(op);
    });

    let html = '<h3>Available Operations</h3>';
    Object.keys(categories).sort().forEach(category => {
      html += `<div class="category">
        <h4>${category}</h4>
        <div class="operations">`;

      categories[category].forEach(op => {
        html += `<button class="operation-btn" data-operation="${op.name}" title="${op.description}">
          ${formatOperationName(op.name)}
        </button>`;
      });

      html += '</div></div>';
    });

    if (operationsPanel) {
      operationsPanel.innerHTML = html;
    }
  }

  // Render current recipe
  function renderRecipe() {
    if (!recipePanel) return;

    if (recipe.length === 0) {
      recipePanel.innerHTML = `<div class="placeholder">
        Add operations from the right panel to build your transformation recipe.
        Click operations to add them to the chain.
      </div>`;
      return;
    }

    let html = '<div class="recipe-steps">';
    recipe.forEach((op, index) => {
      html += `<div class="recipe-step">
        <span class="step-number">${index + 1}</span>
        <span class="step-name">${formatOperationName(op.name)}</span>
        <button class="remove-btn" data-index="${index}" title="Remove">×</button>
      </div>`;
    });
    html += '</div>';

    recipePanel.innerHTML = html;
  }

  // Format operation name for display
  function formatOperationName(name) {
    return name.replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
  }

  // Setup event listeners
  function setupEventListeners() {
    // Input changes trigger auto-transformation
    if (input) {
      input.addEventListener('input', executeRecipe);
    }

    // Operation button clicks
    if (operationsPanel) {
      operationsPanel.addEventListener('click', (e) => {
        if (e.target.classList.contains('operation-btn')) {
          const opName = e.target.dataset.operation;
          addOperationToRecipe(opName);
        }
      });
    }

    // Recipe panel clicks (remove operations)
    if (recipePanel) {
      recipePanel.addEventListener('click', (e) => {
        if (e.target.classList.contains('remove-btn')) {
          const index = parseInt(e.target.dataset.index);
          removeOperationFromRecipe(index);
        }
      });
    }

    // Auto-detect button
    if (detectBtn) {
      detectBtn.addEventListener('click', autoDetect);
    }

    // Clear recipe button
    if (clearRecipeBtn) {
      clearRecipeBtn.addEventListener('click', () => {
        recipe = [];
        renderRecipe();
        executeRecipe();
      });
    }

    // Save recipe button
    if (saveRecipeBtn) {
      saveRecipeBtn.addEventListener('click', saveRecipe);
    }
  }

  // Add operation to recipe
  function addOperationToRecipe(opName) {
    recipe.push({ name: opName });
    renderRecipe();
    executeRecipe();
  }

  // Remove operation from recipe
  function removeOperationFromRecipe(index) {
    recipe.splice(index, 1);
    renderRecipe();
    executeRecipe();
  }

  // Execute recipe on current input
  function executeRecipe() {
    if (!input || !output) return;

    const inputValue = input.value;
    if (!inputValue) {
      output.value = '';
      return;
    }

    if (recipe.length === 0) {
      output.value = inputValue;
      return;
    }

    // For now, show recipe as JSON (will be replaced with actual execution)
    output.value = JSON.stringify({
      note: 'Recipe execution will be implemented via backend API',
      input: inputValue.substring(0, 50) + (inputValue.length > 50 ? '...' : ''),
      recipe: recipe,
      status: 'pending_implementation'
    }, null, 2);
  }

  // Auto-detect encoding
  function autoDetect() {
    if (!input || !output) return;

    const inputValue = input.value.trim();
    if (!inputValue) {
      alert('Please enter some input to detect encoding');
      return;
    }

    // Simulate detection results (will be replaced with actual detection)
    const detections = simulateDetection(inputValue);

    if (detections.length === 0) {
      output.value = 'No encoding detected';
      return;
    }

    output.value = 'Detected encodings:\n\n' +
      detections.map((d, i) =>
        `${i + 1}. ${d.encoding} (${(d.confidence * 100).toFixed(0)}% confidence)\n   ${d.reasoning}\n   Suggested: ${d.operation}`
      ).join('\n\n');
  }

  // Simulate detection (temporary - will use backend)
  function simulateDetection(text) {
    const detections = [];

    // Base64 pattern
    if (/^[A-Za-z0-9+/]+=*$/.test(text)) {
      detections.push({
        encoding: 'base64',
        confidence: 0.9,
        reasoning: 'Matches Base64 pattern',
        operation: 'base64_decode'
      });
    }

    // Hex pattern
    if (/^(0x)?[0-9a-fA-F\s:-]+$/.test(text.replace(/\s/g, '')) && text.replace(/\s/g, '').replace(/0x/g, '').length % 2 === 0) {
      detections.push({
        encoding: 'hex',
        confidence: 0.8,
        reasoning: 'Matches hexadecimal pattern',
        operation: 'hex_decode'
      });
    }

    // URL encoded
    if (/%[0-9A-Fa-f]{2}/.test(text)) {
      const matches = text.match(/%[0-9A-Fa-f]{2}/g);
      detections.push({
        encoding: 'url-encoded',
        confidence: 0.7,
        reasoning: `Contains ${matches.length} URL-encoded sequences`,
        operation: 'url_decode'
      });
    }

    // JWT
    if (text.split('.').length === 3 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)) {
      detections.push({
        encoding: 'jwt',
        confidence: 0.95,
        reasoning: 'Has JWT structure (3 base64url parts)',
        operation: 'jwt_decode'
      });
    }

    return detections.sort((a, b) => b.confidence - a.confidence);
  }

  // Save recipe
  function saveRecipe() {
    if (recipe.length === 0) {
      alert('Recipe is empty. Add some operations first.');
      return;
    }

    const name = prompt('Enter recipe name:');
    if (!name) return;

    const description = prompt('Enter recipe description (optional):') || '';

    const recipeData = {
      name,
      description,
      pipeline: { operations: recipe, reversible: true }
    };

    // Save to localStorage for now (will be replaced with backend API)
    const savedRecipes = JSON.parse(localStorage.getItem('cipher_recipes') || '[]');
    savedRecipes.push(recipeData);
    localStorage.setItem('cipher_recipes', JSON.stringify(savedRecipes));

    alert(`Recipe "${name}" saved successfully!`);
  }

  // Initialize on load
  init();
})();
