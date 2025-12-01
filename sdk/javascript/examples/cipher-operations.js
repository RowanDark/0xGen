/**
 * Cipher Operations Example
 *
 * This example demonstrates how to use the cipher/encoding features:
 * 1. Execute cipher operations
 * 2. Smart decode (auto-detect)
 * 3. Save and load recipes
 */

const { OxGenClient } = require('../dist');

async function main() {
  const client = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL || 'http://localhost:8080',
    apiKey: process.env.OXGEN_API_KEY,
  });

  try {
    // Example 1: Basic cipher operation
    console.log('=== Example 1: Base64 Decode ===');
    const encoded = 'SGVsbG8gV29ybGQh'; // "Hello World!"
    console.log(`Input: ${encoded}`);

    const result1 = await client.executeCipher({
      input: encoded,
      operation: 'base64_decode',
    });
    console.log(`Output: ${result1.output}\n`);

    // Example 2: Smart decode
    console.log('=== Example 2: Smart Decode ===');
    const mystery = 'SGVsbG8gV29ybGQh';
    console.log(`Input: ${mystery}`);

    const result2 = await client.smartDecode(mystery);
    console.log(`Output: ${result2.output}\n`);

    // Example 3: Detect cipher
    console.log('=== Example 3: Detect Cipher ===');
    const detection = await client.detectCipher(encoded);
    console.log('Detection results:', JSON.stringify(detection, null, 2));
    console.log();

    // Example 4: List operations
    console.log('=== Example 4: List Available Operations ===');
    const operations = await client.listCipherOperations();
    console.log(`Available operations: ${operations.length || 'N/A'}`);
    if (operations.operations) {
      operations.operations.slice(0, 10).forEach((op) => {
        console.log(`  - ${op.name || op}`);
      });
    }
    console.log();

    // Example 5: Save and use a recipe
    console.log('=== Example 5: Recipe Management ===');

    // Save a recipe
    console.log('Saving recipe...');
    await client.saveCipherRecipe({
      name: 'example-decode',
      operations: [
        { operation: 'base64_decode' },
        { operation: 'url_decode' },
      ],
    });
    console.log('✓ Recipe saved');

    // List recipes
    const recipes = await client.listCipherRecipes();
    console.log(`Recipes: ${recipes.length}`);
    recipes.forEach((recipe) => {
      console.log(`  - ${recipe.name}`);
    });

    // Load recipe
    const recipe = await client.loadCipherRecipe('example-decode');
    console.log('Loaded recipe:', recipe.name);
    console.log('Operations:', recipe.operations.length);

    // Clean up - delete recipe
    await client.deleteCipherRecipe('example-decode');
    console.log('✓ Recipe deleted');
  } catch (error) {
    console.error('Error:', error.message);
    if (error.status) {
      console.error(`Status Code: ${error.status}`);
    }
    process.exit(1);
  }
}

main();
