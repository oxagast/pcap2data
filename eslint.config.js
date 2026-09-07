// eslint.config.js — PacketSnitch ESLint configuration (flat format, ESLint v9+)

const globals = require('globals');

const pluginNode = require('eslint-plugin-node');
const pluginPromise = require('eslint-plugin-promise');
const pluginImport = require('eslint-plugin-import');

const testFiles = ['tests/**/*.test.js', 'tests/**/*.spec.js'];
const webpackFiles = ['webpack.*.js', 'scripts/**/*.js', 'forge.config.js', '*.spec.js', 'snitch*.spec'];
const srcFiles = ['src/**/*.js'];

const sharedGlobals = {
    ...globals.browser,
    ...globals.node,
    ...globals.es2020,
};

module.exports = [
    // --- Shared globals & parser options ---
    {
        languageOptions: {
            ecmaVersion: 2020,
            sourceType: 'module',
            globals: sharedGlobals,
        },
        plugins: {
            node: pluginNode,
            promise: pluginPromise,
            import: pluginImport,
        },
        rules: {
            // General
            'no-console': 'off',
            'no-debugger': 'warn',
            'no-eval': 'error',
            'no-with': 'error',
            'no-proto': 'error',
            'no-script-url': 'error',

            // Spacing & style
            indent: 'off',
            'linebreak-style': ['error', 'unix'],
            quotes: ['error', 'double', { avoidEscape: true, allowTemplateLiterals: true }],
            'semi': ['error', 'always'],
            'comma-dangle': ['error', 'always-multiline'],
            'max-len': 'off',
            'brace-style': ['error', '1tbs', { allowSingleLine: false }],
            'keyword-spacing': 'error',
            'space-before-blocks': 'error',
            'array-bracket-spacing': ['error', 'never'],
            'object-curly-spacing': ['error', 'always'],
            'comma-spacing': 'error',
            'comma-style': ['error', 'last'],
            'arrow-spacing': 'error',
            'arrow-parens': ['error', 'always'],
            'arrow-body-style': ['error', 'as-needed', { requireReturnForObjectLiteral: false }],
            'consistent-return': 'warn',
            'eqeqeq': ['error', 'always'],
            'yoda': 'error',

            // Best practices
            'consistent-this': ['error', 'self'],
            'no-caller': 'error',
            'no-div-regex': 'error',
            'no-else-return': ['warn', { allowElseIf: false }],
            'no-empty-function': 'error',
            'no-extra-bind': 'error',
            'no-extra-label': 'error',
            'no-floating-decimal': 'error',
            'no-labels': 'error',
            'no-lone-blocks': 'error',
            'no-loop-func': 'error',
            'no-multi-spaces': 'error',
            'no-multi-str': 'error',
            'no-new': 'error',
            'no-new-func': 'error',
            'no-new-wrappers': 'error',
            'no-octal': 'error',
            'no-octal-escape': 'error',
            'no-param-reassign': 'warn',
            'no-redeclare': 'error',
            'no-return-assign': ['error', 'always'],
            'no-self-compare': 'error',
            'no-sequences': 'error',
            'no-throw-literal': 'error',
            'no-unmodified-loop-condition': 'error',
            'no-useless-call': 'warn',
            'no-useless-concat': 'warn',
            'no-useless-escape': 'error',
            'no-useless-return': 'warn',
            'no-void': 'error',
            'no-warning-comments': 'off',
            'prefer-promise-reject-errors': ['error', { allowEmptyReject: true }],
            'require-await': 'off',
            'wrap-iife': ['error', 'outside'],

            // Node / Promise / Import plugin rules (select subset)
            'node/no-missing-import': 'off',
            'node/no-unpublished-require': 'off',
            'promise/always-return': 'off',
            'promise/catch-or-return': 'off',
            'promise/param-names': 'warn',
            'import/order': 'off',
            'import/no-unresolved': 'off',

            // ES2015+
            'object-shorthand': ['error', 'always'],
            'prefer-const': ['error', { destructuring: 'any', ignoreReadBeforeAssign: false }],
            'no-var': 'error',
            'rest-spread-spacing': ['error', 'never'],
            'template-curly-spacing': ['error', 'never'],
            'yield-star-spacing': ['error', 'after'],
            'arrow-body-style': 'off',
        },
    },

    // --- Test files: Jest globals, relaxed rules ---
    {
        files: testFiles,
        languageOptions: {
            globals: {
                ...sharedGlobals,
                ...globals.jest,
            },
        },
        rules: {
            'no-unused-vars': 'off',
            'no-prototype-builtins': 'off',
        },
    },

    // --- Webpack / build scripts ---
    {
        files: webpackFiles,
        languageOptions: {
            globals: sharedGlobals,
        },
        rules: {
            'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
        },
    },

    // --- Src files: strictest ---
    {
        files: srcFiles,
        rules: {
            'no-unused-vars': 'off',
            'no-implicit-globals': 'error',
            'no-shadow': 'off',
            'no-shadow-restricted-names': 'off',
            'no-undef': 'error',
            'no-dupe-keys': 'error',
            'no-duplicate-case': 'error',
            'valid-typeof': 'error',
            'no-empty': 'error',
            'no-ex-assign': 'error',
            'no-const-assign': 'error',
            'no-new-require': 'error',
            'no-path-concat': 'error',
            'no-process-exit': 'error',
            'no-trailing-spaces': 'error',
            'space-infix-ops': 'error',
        },
    },
];
