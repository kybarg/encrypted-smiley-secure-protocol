module.exports = {
  extends: ['eslint:recommended', 'plugin:node/recommended', 'plugin:jest/recommended', 'prettier'],
  plugins: ['node', 'jest'],
  env: {
    node: true,
    'jest/globals': true,
    es6: true,
  },
  parser: '@babel/eslint-parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    requireConfigFile: false,
    babelOptions: {
      plugins: ['@babel/plugin-syntax-import-assertions'],
    },
  },
  globals: {
    makeTestFeature: false,
    shouldReject: false,
  },
  rules: {
    'no-extra-semi': 'off', //prettier does this
    'no-process-exit': 'off',
    'no-var': 'error',
    'node/no-extraneous-import': [
      'error',
      {
        allowModules: ['chai'], //this gets pulled from monorepo root where the tests are run
      },
    ],
    'node/no-missing-import': 'off',
    'node/no-missing-require': 'off',
    'node/no-unpublished-import': 'off',
    'node/no-unpublished-require': 'off',
    'node/no-unsupported-features/es-builtins': 'error',
    'node/no-unsupported-features/es-syntax': 'off',
    'node/no-unsupported-features/node-builtins': 'error',
    'node/shebang': 'off',
    'object-shorthand': 'error',
    'prefer-arrow-callback': 'error',
    'prefer-const': 'error',
    'prefer-template': 'error',
    'jest/no-disabled-tests': 'warn',
    'jest/no-focused-tests': 'error',
    'jest/no-identical-title': 'error',
    'jest/prefer-to-have-length': 'warn',
    'jest/valid-expect': 'error',
    strict: ['error', 'never'],
    'valid-jsdoc': 'off',
  },
}
