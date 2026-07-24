// Prism bundle for the script-editor overlay (bash / python / php; issue #1669).
// Import order matters: prismjs core sets the global Prism object each
// component below extends. php's only declared dependency is
// markup-templating -> markup (components.json), not clike.
import 'prismjs';
import 'prismjs/components/prism-markup';
import 'prismjs/components/prism-markup-templating';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-python';
import 'prismjs/components/prism-php';
