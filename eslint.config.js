const globals = require('globals');
const { defineConfig } = require('eslint/config');
const tseslint = require('typescript-eslint');

module.exports = defineConfig(
  {
    ignores: ['lib/**', 'node_modules/**', 'eslint.config.js', 'babel.config.js'],
  },
  {
    files: ['**/*.ts'],
    extends: [
      tseslint.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: 'tsconfig.json',
        tsconfigRootDir: __dirname,
        sourceType: 'module',
      },
      globals: {
        ...globals.node,
        ...globals.jest,
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": ["off"],
      "@typescript-eslint/no-unused-vars": ["off"],
      "@typescript-eslint/ban-ts-comment": ["off"],
      "@typescript-eslint/no-empty-function": ["off"],
      "@typescript-eslint/no-require-imports": ["off"],
      "@typescript-eslint/no-inferrable-types": ["off"],
      "require-await": ["error"],
      "@typescript-eslint/no-floating-promises": ["error"],
      "max-len": ["off"],
      "semi": ["error"],
      // ESLint 8 (eslintrc, default ecmaVersion) did not check function arguments; keep that behavior
      "comma-dangle": ["error", {
        arrays: "always-multiline",
        objects: "always-multiline",
        imports: "always-multiline",
        exports: "always-multiline",
        functions: "ignore",
      }],
      "eol-last": ["error"],
    },
  },
);
