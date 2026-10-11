import js from "@eslint/js";

const browserGlobals = {
  window: "readonly",
  document: "readonly",
  navigator: "readonly",
  HTMLInputElement: "readonly",
  HTMLButtonElement: "readonly",
  HTMLFormElement: "readonly",
};

export default [
  js.configs.recommended,
  {
    files: ["wwwroot/*.js", "ui-tooling/tests/*.js"],
    languageOptions: { ecmaVersion: 2022, sourceType: "module", globals: browserGlobals },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-globals": ["error", "localStorage", "sessionStorage"],
      "no-restricted-properties": [
        "error",
        { object: "window", property: "localStorage", message: "Nothing may be written to web storage." },
        { object: "window", property: "sessionStorage", message: "Nothing may be written to web storage." },
        { object: "document", property: "write", message: "Do not use document.write." },
      ],
      "no-restricted-syntax": [
        "error",
        { selector: "AssignmentExpression[left.property.name='innerHTML']", message: "Do not assign innerHTML." },
        { selector: "AssignmentExpression[left.property.name='outerHTML']", message: "Do not assign outerHTML." },
      ],
      eqeqeq: "error",
    },
  },
];
