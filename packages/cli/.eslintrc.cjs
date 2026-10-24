/** Minimal lint config: correctness rules only, no stylistic rules. */
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  env: {
    node: true,
    es2022: true,
  },
  ignorePatterns: ['dist/', 'node_modules/', 'bin/'],
  rules: {
    // tsc already enforces unused locals with the project settings; keep the
    // underscore convention for intentionally unused parameters.
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-non-null-assertion': 'off',
  },
};
