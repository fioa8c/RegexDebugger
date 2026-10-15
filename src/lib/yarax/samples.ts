export const YARA_DEFAULT_PATTERN = 'eval\\s*\\(\\s*base64_decode\\s*\\('

export const YARA_SAMPLE_INPUT =
  '<?php\n' +
  '// matches\n' +
  "eval(base64_decode('ZWNobyAnaGknOw=='));\n" +
  '// near-miss: evaluate / base64_encode\n' +
  'evaluate(base64_encode($x));\n' +
  '// extra spaces still match\n' +
  'eval ( base64_decode ( $payload ) );\n'
