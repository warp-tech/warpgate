// eslint.config.cjs

import globals from "globals";
import eslintPluginSvelte from 'eslint-plugin-svelte';
import js from '@eslint/js';
import svelteParser from 'svelte-eslint-parser';
import tsEslint from 'typescript-eslint';
import tsParser from '@typescript-eslint/parser';
import stylistic from '@stylistic/eslint-plugin'

export default [
  js.configs.recommended,
  ...tsEslint.configs.strict,
  ...eslintPluginSvelte.configs['flat/recommended'],
  {
    ignores: ["**/svelte.config.js", "**/vite.config.ts", "src/*/lib/api-client/**/*"],
  },
  {
    plugins: {
        '@stylistic': stylistic,
    },
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
        parser: tsParser,
        extraFileExtensions: [".svelte"],
      },
      globals: {
          ...globals.browser,
          T: false,
      },
    },
    rules: {
        "@stylistic/semi": ["error", "never"],
        "@stylistic/indent": ["error", 4],

        "@typescript-eslint/explicit-member-accessibility": ["error", {
            accessibility: "no-public",

            overrides: {
                parameterProperties: "explicit",
            },
        }],

        "@typescript-eslint/no-require-imports": "off",
        "@typescript-eslint/no-parameter-properties": "off",
        "@typescript-eslint/explicit-function-return-type": "off",
        "@typescript-eslint/no-explicit-any": "off",
        "@typescript-eslint/no-magic-numbers": "off",
        "@typescript-eslint/member-delimiter-style": "off",
        "@typescript-eslint/promise-function-async": "off",
        "@typescript-eslint/require-array-sort-compare": "off",
        "@typescript-eslint/no-floating-promises": "off",
        "@typescript-eslint/prefer-readonly": "off",
        "@typescript-eslint/require-await": "off",
        "@typescript-eslint/strict-boolean-expressions": "off",
        "@typescript-eslint/explicit-module-boundary-types": "error",

        // "@typescript-eslint/no-misused-promises": ["error", {
        //     checksVoidReturn: false,
        // }],

        "@typescript-eslint/typedef": "off",
        "@typescript-eslint/consistent-type-imports": "off",
        "@typescript-eslint/sort-type-union-intersection-members": "off",

        "@typescript-eslint/no-use-before-define": ["error", {
            classes: false,
            functions: false,
        }],

        "no-duplicate-imports": "error",
        "array-bracket-spacing": ["error", "never"],
        "block-scoped-var": "error",
        "brace-style": "off",

        "@stylistic/brace-style": ["error", "1tbs", {
            allowSingleLine: true,
        }],

        "computed-property-spacing": ["error", "never"],
        curly: "error",
        "eol-last": "error",
        eqeqeq: ["error", "smart"],
        "max-depth": [1, 5],
        "max-statements": [1, 80],
        "no-multiple-empty-lines": "error",
        "no-mixed-spaces-and-tabs": "error",
        "no-trailing-spaces": "error",

        "@typescript-eslint/no-unused-vars": ["error", {
            vars: "all",
            args: "after-used",
            argsIgnorePattern: "^_",
        }],

        "no-undef": "error",
        "no-var": "error",
        "object-curly-spacing": "off",
        "@stylistic/object-curly-spacing": ["error", "always"],

        "quote-props": ["warn", "as-needed", {
            keywords: true,
            numbers: true,
        }],

        quotes: "off",

        "@stylistic/quotes": ["error", "single", {
            allowTemplateLiterals: true,
        }],

        "@typescript-eslint/no-confusing-void-expression": ["error", {
            ignoreArrowShorthand: true,
        }],

        "@typescript-eslint/no-non-null-assertion": "off",

        // "@typescript-eslint/no-unnecessary-condition": ["error", {
        //     allowConstantLoopConditions: true,
        // }],

        "@typescript-eslint/restrict-template-expressions": "off",
        "@typescript-eslint/prefer-readonly-parameter-types": "off",
        "@typescript-eslint/no-unsafe-member-access": "off",
        "@typescript-eslint/no-unsafe-call": "off",
        "@typescript-eslint/no-unsafe-return": "off",
        "@typescript-eslint/no-unsafe-assignment": "off",
        "@typescript-eslint/naming-convention": "off",

        "@stylistic/lines-between-class-members": ["error", "always", {
            exceptAfterSingleLine: true,
        }],

        "@typescript-eslint/dot-notation": "off",
        "@typescript-eslint/no-implicit-any-catch": "off",
        "@typescript-eslint/member-ordering": "off",
        "@typescript-eslint/no-var-requires": "off",
        "@typescript-eslint/no-unsafe-argument": "off",
        "@typescript-eslint/restrict-plus-operands": "off",
        "@typescript-eslint/space-infix-ops": "off",

        "@typescript-eslint/no-type-alias": ["error", {
            allowAliases: "in-unions-and-intersections",
            allowLiterals: "always",
            allowCallbacks: "always",
        }],

        "@stylistic/comma-dangle": ["error", {
            arrays: "always-multiline",
            objects: "always-multiline",
            imports: "always-multiline",
            exports: "always-multiline",
            functions: "only-multiline",
        }],

        "@typescript-eslint/use-unknown-in-catch-callback-variable": "off",
    },
  },
  {
    files: ['**/*.svelte'],
    languageOptions: {
      parser: svelteParser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
        parser: tsParser,
      },
    },
    rules: {
      'svelte/no-target-blank': 'error',
      'svelte/no-at-debug-tags': 'error',
      'svelte/no-reactive-functions': 'error',
      'svelte/no-reactive-literals': 'error',
    },
  },
];
