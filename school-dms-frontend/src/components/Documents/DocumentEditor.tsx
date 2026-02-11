// src/components/Documents/DocumentEditor.tsx
import React, { useState, useEffect, useRef } from "react";
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import BulletList from '@tiptap/extension-bullet-list';
import OrderedList from '@tiptap/extension-ordered-list';
import Placeholder from '@tiptap/extension-placeholder';
import CharacterCount from '@tiptap/extension-character-count';
import Link from '@tiptap/extension-link';
import Image from '@tiptap/extension-image';
import { Table } from '@tiptap/extension-table';
import { TableRow } from '@tiptap/extension-table-row';
import { TableCell } from '@tiptap/extension-table-cell';
import { TableHeader } from '@tiptap/extension-table-header';
import { TextAlign } from '@tiptap/extension-text-align';
import { TextStyle } from '@tiptap/extension-text-style';
import Color from '@tiptap/extension-color';
import Underline from '@tiptap/extension-underline';
import Subscript from '@tiptap/extension-subscript';
import Superscript from '@tiptap/extension-superscript';
import Highlight from '@tiptap/extension-highlight';
import Blockquote from '@tiptap/extension-blockquote';
import HorizontalRule from '@tiptap/extension-horizontal-rule';
import CodeBlock from '@tiptap/extension-code-block';
import CodeBlockLowlight from '@tiptap/extension-code-block-lowlight';
import YouTube from '@tiptap/extension-youtube';
import TaskList from '@tiptap/extension-task-list';
import TaskItem from '@tiptap/extension-task-item';
import Gapcursor from '@tiptap/extension-gapcursor';
import HardBreak from '@tiptap/extension-hard-break';

import { createLowlight } from 'lowlight';
import './DocumentEditor.css';

// Note: Common languages are pre-loaded with lowlight
// If needed, you can import additional languages:
// import javascript from 'highlight.js/lib/languages/javascript';
// import typescript from 'highlight.js/lib/languages/typescript';

type Doc = {
  id: number;
  title: string;
  filename: string;
  filepath?: string;
  mime_type?: string;
  file_size?: number;
};

type Props = {
  document: Doc;
  onClose: () => void;
  onSave: (content: string, note: string) => void;
};

const API = (import.meta.env.VITE_API_URL as string) || "http://localhost:4000";

// Create lowlight instance with common languages
const lowlight = createLowlight({
  // Common languages are included by default
  // You can add more if needed
});

export default function DocumentEditor({ document, onClose, onSave }: Props) {
  const [content, setContent] = useState("");
  const [originalContent, setOriginalContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saveStatus, setSaveStatus] = useState<string>("");
  const [documentFormat, setDocumentFormat] = useState<string>("text");
  const [isRichText, setIsRichText] = useState(false);
  const [showLinkDialog, setShowLinkDialog] = useState(false);
  const [linkUrl, setLinkUrl] = useState("");
  const [linkText, setLinkText] = useState("");
  const [showImageDialog, setShowImageDialog] = useState(false);
  const [imageUrl, setImageUrl] = useState("");
  const [showTableDialog, setShowTableDialog] = useState(false);
  const [tableRows, setTableRows] = useState(3);
  const [tableCols, setTableCols] = useState(3);
  const [showYoutubeDialog, setShowYoutubeDialog] = useState(false);
  const [youtubeUrl, setYoutubeUrl] = useState("");
  const [showColorPalette, setShowColorPalette] = useState(false);
  const editorRef = useRef<HTMLTextAreaElement>(null);

  // Initialize TipTap editor with comprehensive extensions
  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        codeBlock: false, // Disable default CodeBlock to use CodeBlockLowlight instead
        bulletList: false, // Disable default BulletList to use custom extension
        orderedList: false, // Disable default OrderedList to use custom extension
        pasteRules: false, // Disable paste rules to avoid clipboard issues
      }),
      BulletList.configure({
        HTMLAttributes: {
          class: 'bullet-list',
        },
      }),
      OrderedList.configure({
        HTMLAttributes: {
          class: 'ordered-list',
        },
      }),
      Placeholder.configure({
        placeholder: 'Start typing your document content...',
      }),
      CharacterCount.configure({
        limit: 100000,
      }),
      Link.configure({
        openOnClick: false,
        linkOnPaste: false, // Disable clipboard paste behavior
        autolink: false, // Disable automatic linking
        HTMLAttributes: {
          class: 'text-blue-600 underline hover:text-blue-800',
        },
      }),
      Image.configure({
        HTMLAttributes: {
          class: 'max-w-full h-auto rounded-lg',
        },
      }),
      Table.configure({
        resizable: true,
        HTMLAttributes: {
          class: 'border-collapse border border-gray-300',
        },
      }),
      TableRow.configure({
        HTMLAttributes: {
          class: 'border border-gray-300',
        },
      }),
      TableHeader.configure({
        HTMLAttributes: {
          class: 'border border-gray-300 bg-gray-50 px-4 py-2 text-left font-semibold',
        },
      }),
      TableCell.configure({
        HTMLAttributes: {
          class: 'border border-gray-300 px-4 py-2',
        },
      }),
      TextAlign.configure({
        types: ['heading', 'paragraph'],
      }),
      TextStyle,
      Color.configure({
        types: ['textStyle'],
      }),
      Underline,
      Subscript,
      Superscript,
      Highlight.configure({
        multicolor: true,
      }),
      Blockquote.configure({
        HTMLAttributes: {
          class: 'border-l-4 border-gray-300 pl-4 italic',
        },
      }),
      HorizontalRule,
      CodeBlockLowlight.configure({
        lowlight,
        HTMLAttributes: {
          class: 'bg-gray-900 text-gray-100 rounded-md p-4 font-mono text-sm overflow-x-auto',
        },
        exitOnTripleEnter: false, // Disable clipboard-related shortcuts
      }),
      YouTube.configure({
        controls: false,
        nocookie: true,
        HTMLAttributes: {
          class: 'rounded-lg',
        },
      }),
      TaskList.configure({
        HTMLAttributes: {
          class: 'task-list',
        },
      }),
      TaskItem.configure({
        HTMLAttributes: {
          class: 'task-item',
        },
        nested: true,
        insertTaskWithTasksHTML: false,
      }),
      Gapcursor,
      HardBreak,
    ],
    content: content,
    onUpdate: ({ editor }) => {
      const newContent = editor.getHTML();
      setContent(newContent);
    },
    editable: !loading && !saving,
    immediatelyRender: false,
  });

  // Handle keyboard shortcuts for large document navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      try {
        // Ctrl+S for saving
        if (e.ctrlKey && e.key === 's') {
          e.preventDefault();
          handleSave();
          return;
        }
        
        // Ctrl+Home for scrolling to top
        if (e.ctrlKey && e.key === 'Home') {
          e.preventDefault();
          if (editor) {
            editor.commands.focus('start');
            const editorElement = editor.view.dom;
            if (editorElement) {
              editorElement.scrollTop = 0;
            }
          } else {
            const textarea = editorRef.current;
            if (textarea) {
              textarea.setSelectionRange(0, 0);
              textarea.scrollTop = 0;
            }
          }
          return;
        }
        
        // Ctrl+End for scrolling to bottom
        if (e.ctrlKey && e.key === 'End') {
          e.preventDefault();
          if (editor) {
            editor.commands.focus('end');
            const editorElement = editor.view.dom;
            if (editorElement) {
              editorElement.scrollTop = editorElement.scrollHeight;
            }
          } else {
            const textarea = editorRef.current;
            if (textarea) {
              textarea.setSelectionRange(textarea.value.length, textarea.value.length);
              textarea.scrollTop = textarea.scrollHeight;
            }
          }
          return;
        }
      } catch (err) {
        console.warn('Keyboard shortcut error:', err);
      }
    };

    if (typeof window !== 'undefined' && window.addEventListener) {
      window.addEventListener('keydown', handleKeyDown);
      return () => {
        if (typeof window !== 'undefined' && window.removeEventListener) {
          window.removeEventListener('keydown', handleKeyDown);
        }
      };
    }
  }, [content, note, editor]);

  // Close color palette when clicking outside or pressing Escape
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (showColorPalette && e.target instanceof Element && !e.target.closest('.color-picker-container')) {
        setShowColorPalette(false);
      }
    };

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowColorPalette(false);
      }
    };

    if (showColorPalette && typeof window !== 'undefined' && window.document) {
      window.document.addEventListener('mousedown', handleClickOutside);
      window.addEventListener('keydown', handleEscape);
      return () => {
        if (typeof window !== 'undefined' && window.document) {
          window.document.removeEventListener('mousedown', handleClickOutside);
          window.removeEventListener('keydown', handleEscape);
        }
      };
    }
  }, [showColorPalette]);

  // Update editor content when document loads
  useEffect(() => {
    if (editor && content !== editor.getHTML()) {
      editor.commands.setContent(content);
    }
  }, [content, editor]);

  // Cleanup editor on unmount
  useEffect(() => {
    return () => {
      if (editor) {
        editor.destroy();
      }
    };
  }, [editor]);

  // Load document content
  useEffect(() => {
    const loadContent = async () => {
      setLoading(true);
      setError(null);
      try {
        const token = localStorage.getItem("token");
        const res = await fetch(`${API}/api/documents/${document.id}/content`, {
          headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({ message: res.statusText }));
          throw new Error(body.message || "Failed to load document content");
        }

        const data = await res.json();
        setContent(data.content || "");
        setOriginalContent(data.content || "");
        setDocumentFormat(data.format || "text");
      } catch (err: any) {
        setError(err.message || "Failed to load document");
      } finally {
        setLoading(false);
      }
    };

    loadContent();
  }, [document.id]);

  // Get editor configuration
  const getEditorConfig = () => {
    const key = documentFormat === "markdown" ? "office_markdown" : document.mime_type;
    
    if (!key) return { placeholder: "Start typing your document content...", mode: "text", language: "plaintext", title: "Document", richText: true };
    
    const configMap: { [key: string]: { placeholder: string; mode: string; language: string; title: string; richText?: boolean } } = {
      "text/plain": { 
        placeholder: "Start typing your plain text document...", 
        mode: "text", 
        language: "plaintext",
        title: "Plain Text",
        richText: true
      },
      "text/html": { 
        placeholder: "<!DOCTYPE html>\\n<html>\\n<head>\\n  <title>Document</title>\\n</head>\\n<body>\\n  \\n</body>\\n</html>", 
        mode: "html", 
        language: "html",
        title: "HTML Document"
      },
      "text/css": { 
        placeholder: "/* CSS Styles */\\nbody {\\n  \\n}", 
        mode: "css", 
        language: "css",
        title: "CSS Stylesheet"
      },
      "text/javascript": { 
        placeholder: "// JavaScript code\\nconsole.log('Hello World');", 
        mode: "javascript", 
        language: "javascript",
        title: "JavaScript"
      },
      "application/javascript": { 
        placeholder: "// JavaScript code\\nconsole.log('Hello World');", 
        mode: "javascript", 
        language: "javascript",
        title: "JavaScript"
      },
      "application/json": { 
        placeholder: '{\\n  "key": "value"\\n}', 
        mode: "json", 
        language: "json",
        title: "JSON"
      },
      "application/xml": { 
        placeholder: '<?xml version="1.0" encoding="UTF-8"?>\\n<root>\\n  \\n</root>', 
        mode: "xml", 
        language: "xml",
        title: "XML"
      },
      "text/xml": { 
        placeholder: '<?xml version="1.0" encoding="UTF-8"?>\\n<root>\\n  \\n</root>', 
        mode: "xml", 
        language: "xml",
        title: "XML"
      },
      "text/markdown": { 
        placeholder: "# Document Title\\n\\n## Section\\n\\nYour content here...", 
        mode: "markdown", 
        language: "markdown",
        title: "Markdown"
      },
      "text/csv": { 
        placeholder: "Header1,Header2,Header3\\nValue1,Value2,Value3", 
        mode: "csv", 
        language: "csv",
        title: "CSV"
      },
      "text/yaml": { 
        placeholder: "# YAML Configuration\\nkey: value\\nnested:\\n  item: value", 
        mode: "yaml", 
        language: "yaml",
        title: "YAML"
      },
      "application/x-yaml": { 
        placeholder: "# YAML Configuration\\nkey: value\\nnested:\\n  item: value", 
        mode: "yaml", 
        language: "yaml",
        title: "YAML"
      },
      "office_markdown": {
        placeholder: "# Document Content\\n\\nEdit your document content here using rich text formatting.\\n\\n## Section\\n\\nYour text content goes here...",
        mode: "richtext",
        language: "Rich Text",
        title: "Office Document",
        richText: true
      }
    };

    return configMap[key] || { placeholder: "Start typing your document content...", mode: "text", language: "plaintext", title: "Document", richText: true };
  };

  const editorConfig = getEditorConfig();

  // Update rich text mode based on document type
  useEffect(() => {
    setIsRichText(!!editorConfig.richText);
  }, [editorConfig]);

  // Handle save
  const handleSave = async () => {
    const contentToSave = isRichText && editor ? editor.getHTML() : content;
    
    if (!contentToSave.trim()) {
      setError("Document content cannot be empty");
      return;
    }

    setSaving(true);
    setError(null);
    setSaveStatus("Saving...");

    try {
      await onSave(contentToSave, note);
      setOriginalContent(contentToSave);
      setNote("");
      setSaveStatus("Saved successfully!");
      
      setTimeout(() => setSaveStatus(""), 2000);
    } catch (err: any) {
      setError(err.message || "Failed to save document");
      setSaveStatus("");
    } finally {
      setSaving(false);
    }
  };

  // Handle close with unsaved changes warning
  const handleClose = () => {
    const currentContent = isRichText && editor ? editor.getHTML() : content;
    if (currentContent !== originalContent) {
      if (window.confirm("You have unsaved changes. Are you sure you want to close?")) {
        onClose();
      }
    } else {
      onClose();
    }
  };

  // Get file icon based on mime type
  const getFileIcon = () => {
    if (!document.mime_type) return "📄";
    
    const typeMap: { [key: string]: string } = {
      "text/plain": "📝",
      "text/html": "🌐",
      "text/css": "🎨",
      "text/javascript": "⚡",
      "application/json": "📋",
      "application/xml": "📄",
      "text/markdown": "📝",
      "text/csv": "📊",
    };

    return typeMap[document.mime_type] || "📄";
  };

  // Handle download edited document
  const handleDownload = async () => {
    try {
      let currentContent = isRichText && editor ? editor.getHTML() : content;
      
      // Determine file extension and MIME type
      let fileExtension = '.txt';
      let mimeType = 'text/plain';
      
      if (isRichText && currentContent.includes('<')) {
        // For rich text content, save as proper HTML document
        fileExtension = '.html';
        mimeType = 'text/html';
        // Create proper HTML document structure
        const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${document.title}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
        h1 { font-size: 24px; margin: 20px 0 10px 0; }
        h2 { font-size: 20px; margin: 15px 0 8px 0; }
        h3 { font-size: 16px; margin: 10px 0 6px 0; }
        ul, ol { margin: 10px 0; padding-left: 20px; }
        li { margin: 5px 0; }
        blockquote { border-left: 3px solid #ccc; margin: 10px 0; padding-left: 15px; color: #666; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    ${currentContent}
</body>
</html>`;
        currentContent = htmlTemplate;
      } else if (documentFormat === 'javascript') {
        fileExtension = '.js';
        mimeType = 'text/javascript';
      } else if (documentFormat === 'json') {
        fileExtension = '.json';
        mimeType = 'application/json';
      } else if (documentFormat === 'css') {
        fileExtension = '.css';
        mimeType = 'text/css';
      } else if (documentFormat === 'markdown') {
        fileExtension = '.md';
        mimeType = 'text/markdown';
      }
      
      // Create blob with appropriate MIME type
      const blob = new Blob([currentContent], { type: mimeType });
      const blobUrl = window.URL.createObjectURL(blob);
      
      // Create download link with better error handling
      const link = window.document.createElement('a');
      link.href = blobUrl;
      link.style.display = 'none';
      
      // Generate filename
      const docFilename = document.filename.replace(/\.[^/.]+$/, ""); // Remove existing extension
      link.download = `${docFilename}_edited${fileExtension}`;
      
      // Trigger download with multiple fallback methods
      try {
        // Method 1: Add to DOM and click
        window.document.body.appendChild(link);
        link.click();
        
        // Method 2: Fallback for browsers that don't support programmatic clicks
        setTimeout(() => {
          if (window.document.body.contains(link)) {
            window.document.body.removeChild(link);
          }
        }, 100);
        
      } catch (clickError) {
        // Method 3: Manual download prompt - open in new tab
        try {
          window.open(blobUrl, '_blank');
        } catch (openError) {
          // Method 4: Last resort - create a data URL
          const reader = new FileReader();
          reader.onloadend = () => {
            const dataUrl = reader.result;
            const newLink = window.document.createElement('a');
            newLink.href = dataUrl as string;
            newLink.download = `${docFilename}_edited${fileExtension}`;
            newLink.click();
          };
          reader.readAsDataURL(blob);
        }
      }
      
      // Clean up blob URL
      setTimeout(() => {
        try {
          window.URL.revokeObjectURL(blobUrl);
        } catch (revokeError) {
          console.warn('Failed to revoke blob URL:', revokeError);
        }
      }, 5000);
      
      setSaveStatus("Downloaded successfully!");
      setTimeout(() => setSaveStatus(""), 3000);
      
      // Show helpful message about file location
      setTimeout(() => {
        const downloadedFileExtension = fileExtension;
        const isHtml = downloadedFileExtension === '.html';
        
        let message = `Document downloaded successfully!\n\n📁 File location: Check your Downloads folder\n📄 Filename: ${docFilename}_edited${downloadedFileExtension}\n\n`;
        
        if (isHtml) {
          message += `🌐 To open: Double-click the file or right-click → "Open with" → Choose your web browser\n\n`;
          message += `💡 The HTML file contains your formatted document and will open in any browser (Chrome, Firefox, Safari, etc.)`;
        } else {
          message += `💡 To open: Double-click the file or open with the appropriate application`;
        }
        
        // Only show alert if not in production mode to avoid spam
        if (import.meta.env.MODE !== 'production') {
          console.log('Download info:', message);
        }
      }, 1000);
      
    } catch (err: any) {
      console.error('Download error:', err);
      setError(`Failed to download document: ${err.message || 'Unknown error'}`);
    }
  };

  // Link dialog handlers
  const handleAddLink = () => {
    if (linkUrl) {
      editor?.chain().focus().setLink({ href: linkUrl }).run();
      setShowLinkDialog(false);
      setLinkUrl("");
      setLinkText("");
    }
  };

  // Image dialog handlers
  const handleAddImage = () => {
    if (imageUrl) {
      editor?.chain().focus().setImage({ src: imageUrl }).run();
      setShowImageDialog(false);
      setImageUrl("");
    }
  };

  // Table dialog handlers
  const handleInsertTable = () => {
    editor?.chain().focus().insertTable({ rows: tableRows, cols: tableCols, withHeaderRow: true }).run();
    setShowTableDialog(false);
    setTableRows(3);
    setTableCols(3);
  };

  // YouTube dialog handlers
  const handleAddYouTube = () => {
    if (youtubeUrl) {
      editor?.chain().focus().setYoutubeVideo({ src: youtubeUrl }).run();
      setShowYoutubeDialog(false);
      setYoutubeUrl("");
    }
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-6 max-w-sm w-full mx-4">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
            <p className="text-gray-600">Loading document...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-7xl h-[95vh] mx-4 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">{getFileIcon()}</span>
            <div>
              <h3 className="text-lg font-semibold text-gray-900">{document.title}</h3>
              <p className="text-sm text-gray-500">{document.filename}</p>
               <div className="flex items-center space-x-2">
                 <span className="text-xs text-gray-400">Type: {editorConfig.title}</span>
                 <span className="text-xs text-gray-400">• Press Ctrl+S to save</span>
                 <span className="text-xs text-gray-400">• Ctrl+Home/End to navigate</span>
               </div>
            </div>
          </div>
            <div className="flex items-center space-x-3">
              {saveStatus && (
                <span className={`text-sm ${saveStatus.includes('uccess') ? 'text-green-600' : 'text-blue-600'}`}>
                  {saveStatus}
                </span>
              )}
              <button
                onClick={handleDownload}
                className="text-gray-400 hover:text-gray-600 transition-colors"
                title="Download edited document"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </button>
              <button
                onClick={handleClose}
                className="text-gray-400 hover:text-gray-600 transition-colors"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
        </div>

        {/* Content */}
        <div className="flex-1 p-4 overflow-hidden flex flex-col">
          <div className="relative flex-1">
            <div className="absolute top-2 right-2 z-10 flex items-center space-x-2">
              <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded-md font-mono">
                {editorConfig.language.toUpperCase()}
              </span>
              {isRichText && editor && (
                <>
                  <span className="text-xs bg-blue-100 text-blue-600 px-2 py-1 rounded-md">
                    {editor.storage.characterCount.characters()} chars
                  </span>
                  <span className="text-xs bg-green-100 text-green-600 px-2 py-1 rounded-md">
                    {Math.round(editor.storage.characterCount.words())} words
                  </span>
                </>
              )}
            </div>
            
            {isRichText ? (
              <div className="h-full pt-8">
                {/* Comprehensive Rich Text Editor Toolbar */}
                <div className="border border-gray-300 rounded-t-lg bg-gray-50 p-2 overflow-x-auto">
                  <div className="flex items-center space-x-1 min-w-max">
                    {/* Text Formatting */}
                    <div className="flex items-center space-x-1 pr-2 border-r border-gray-300">
                      <button
                        onClick={() => editor?.chain().focus().toggleBold().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('bold') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Bold"
                      >
                        <svg className="w-4 h-4 font-bold" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M15.6 10.79c.97-.67 1.65-1.77 1.65-2.79 0-2.26-1.75-4-4-4H7v14h7.04c2.09 0 3.71-1.7 3.71-3.79 0-1.52-.86-2.82-2.15-3.42zM10 6.5h3c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5h-3v-3zm3.5 9H10v-3h3.5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleItalic().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('italic') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Italic"
                      >
                        <svg className="w-4 h-4 italic" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M10 4v3h2.21l-3.42 8H6v3h8v-3h-2.21l3.42-8H18V4z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleUnderline().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('underline') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Underline"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M12 17c3.31 0 6-2.69 6-6V3h-2.5v8c0 1.93-1.57 3.5-3.5 3.5S8.5 12.93 8.5 11V3H6v8c0 3.31 2.69 6 6 6zm-7 2v2h14v-2H5z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleStrike().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('strike') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Strikethrough"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M10 19h4v-3h-4v3zM5 4v3h5v3h4V7h5V4H5zM3 14h18v-2H3v2z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleSubscript().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('subscript') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Subscript"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M16 9l-3.5-4.5L9 9H7l4-5-4-5h2l3.5 4.5L16-1h2l-4 5 4 5h-2z"/>
                          <text x="8" y="22" fontSize="8" fill="currentColor">X₂</text>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleSuperscript().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('superscript') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Superscript"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M7 7V9h10V7h-3l3-4h-2.5L12 5.5L9.5 3H7l3 4H7z"/>
                          <text x="8" y="22" fontSize="8" fill="currentColor">X²</text>
                        </svg>
                      </button>
                    </div>

                    {/* Text Color & Highlight */}
                    <div className="flex items-center space-x-1 pr-2 border-r border-gray-300">
                      <div className="relative color-picker-container">
                        <button
                          onClick={() => setShowColorPalette(!showColorPalette)}
                          className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                          title="Text Color"
                        >
                          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9c.83 0 1.5-.67 1.5-1.5 0-.39-.15-.74-.39-1.01-.23-.26-.38-.61-.38-.99 0-.83.67-1.5 1.5-1.5H16c2.76 0 5-2.24 5-5 0-4.42-4.03-8-9-8zm-5.5 9c-.83 0-1.5-.67-1.5-1.5S5.67 9 6.5 9 8 9.67 8 10.5 7.33 12 6.5 12zm3-4C8.67 8 8 7.33 8 6.5S8.67 5 9.5 5s1.5.67 1.5 1.5S10.33 8 9.5 8zm5 0c-.83 0-1.5-.67-1.5-1.5S13.67 5 14.5 5s1.5.67 1.5 1.5S15.33 8 14.5 8z"/>
                          </svg>
                          <span className="ml-1 text-xs">Color</span>
                        </button>
                        
                        {showColorPalette && (
                          <>
                            {/* Overlay backdrop */}
                            <div 
                              className="fixed inset-0 bg-black bg-opacity-20 z-[9998]"
                              onClick={() => setShowColorPalette(false)}
                            />
                            
                            {/* Color palette */}
                            <div className="fixed bg-white border border-gray-300 rounded-lg shadow-xl p-3 w-64 z-[9999]" 
                                 style={{ 
                                   top: '50%', 
                                   left: '50%',
                                   transform: 'translate(-50%, -50%)',
                                   maxHeight: '80vh',
                                   overflowY: 'auto'
                                 }}>
                            <div className="mb-3">
                              <label className="block text-xs font-medium text-gray-700 mb-1">Custom Color</label>
                              <div className="flex items-center space-x-2">
                                <input
                                  type="color"
                                  onChange={(e) => {
                                    editor?.chain().focus().setColor(e.target.value).run();
                                    setShowColorPalette(false);
                                  }}
                                  className="w-16 h-10 border border-gray-300 rounded cursor-pointer"
                                />
                                <input
                                  type="text"
                                  placeholder="#000000"
                                  className="flex-1 px-2 py-1 text-xs border border-gray-300 rounded"
                                  onChange={(e) => {
                                    const color = e.target.value;
                                    if (/^#[0-9A-Fa-f]{6}$/.test(color)) {
                                      editor?.chain().focus().setColor(color).run();
                                    }
                                  }}
                                />
                              </div>
                            </div>
                            
                            <div className="space-y-2">
                              <label className="block text-xs font-medium text-gray-700">Quick Colors</label>
                              <div className="grid grid-cols-8 gap-1">
                                {[
                                  '#000000', '#434343', '#666666', '#999999', '#b7b7b7', '#cccccc', '#d9d9d9', '#ffffff',
                                  '#980000', '#ff0000', '#ff9900', '#ffff00', '#00ff00', '#00ffff', '#4a86e8', '#0000ff',
                                  '#990033', '#cc6633', '#ffcc00', '#99cc00', '#339966', '#33cccc', '#3366ff', '#800080',
                                  '#969696', '#ff99cc', '#ffcc99', '#ffff99', '#ccffcc', '#ccffff', '#99ccff', '#cc99ff'
                                ].map((color) => (
                                  <button
                                    key={color}
                                    onClick={() => {
                                      editor?.chain().focus().setColor(color).run();
                                      setShowColorPalette(false);
                                    }}
                                    className="w-7 h-7 rounded border border-gray-200 hover:scale-110 transition-transform"
                                    style={{ backgroundColor: color }}
                                    title={color}
                                  />
                                ))}
                              </div>
                            </div>
                            
                            <div className="mt-3 flex justify-between">
                              <button
                                onClick={() => {
                                  editor?.chain().focus().unsetColor().run();
                                  setShowColorPalette(false);
                                }}
                                className="px-3 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded transition-colors"
                              >
                                Default
                              </button>
                              <button
                                onClick={() => setShowColorPalette(false)}
                                className="px-3 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded transition-colors"
                              >
                                Close
                              </button>
                            </div>
                          </div>
                            </>
                        )}
                      </div>
                      <button
                        onClick={() => editor?.chain().focus().toggleHighlight().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('highlight') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Highlight"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M12 3l-1 3h2l-1-3zm0 4l-7 7h4l3 9 3-9h4l-7-7z"/>
                        </svg>
                        <span className="ml-1 text-xs">Highlight</span>
                      </button>
                    </div>

                    {/* Headings */}
                    <div className="flex items-center space-x-1 pr-2 border-r border-gray-300">
                      <button
                        onClick={() => editor?.chain().focus().toggleHeading({ level: 1 }).run()}
                        className={`px-3 py-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center font-bold text-sm ${editor?.isActive('heading', { level: 1 }) ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Heading 1"
                      >
                        H1
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleHeading({ level: 2 }).run()}
                        className={`px-3 py-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center font-bold text-sm ${editor?.isActive('heading', { level: 2 }) ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Heading 2"
                      >
                        H2
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleHeading({ level: 3 }).run()}
                        className={`px-3 py-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center font-bold text-sm ${editor?.isActive('heading', { level: 3 }) ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Heading 3"
                      >
                        H3
                      </button>
                    </div>

{/* Text Alignment */}
                    <div className="flex items-center space-x-1 pr-2 border-r border-gray-300">
                      <button
                        onClick={() => editor?.chain().focus().setTextAlign('left').run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive({ textAlign: 'left' }) ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Align Left"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M15 15H3v2h12v-2zm0-8H3v2h12V7zM3 13h18v-2H3v2zm0 8h18v-2H3v2zM3 3v2h18V3H3z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().setTextAlign('center').run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive({ textAlign: 'center' }) ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Align Center"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M7 15v2h10v-2H7zm-4 6h18v-2H3v2zm0-8h18v-2H3v2zm4-6v2h10V7H7zM3 3v2h18V3H3z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().setTextAlign('right').run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive({ textAlign: 'right' }) ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Align Right"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M3 21h18v-2H3v2zm0-4h18v-2H3v2zm0-4h18v-2H3v2zm6-4h12V7H9v2zm-6-6h2V3H3v2z"/>
                        </svg>
                      </button>
                    </div>

                    {/* Lists */}
                    <div className="flex items-center space-x-1 pr-2 border-r border-gray-300">
                      <button
                        onClick={() => editor?.chain().focus().toggleBulletList().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('bulletList') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Bullet List"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M4 10.5c-.83 0-1.5.67-1.5 1.5s.67 1.5 1.5 1.5 1.5-.67 1.5-1.5-.67-1.5-1.5-1.5zm0-6c-.83 0-1.5.67-1.5 1.5S3.17 7.5 4 7.5 5.5 6.83 5.5 6 4.83 4.5 4 4.5zm0 12c-.83 0-1.5.68-1.5 1.5s.68 1.5 1.5 1.5 1.5-.68 1.5-1.5-.67-1.5-1.5-1.5zM7 19h14v-2H7v2zm0-6h14v-2H7v2zm0-8v2h14V5H7z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleOrderedList().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('orderedList') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Numbered List"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M2 17h2v.5H3v1h1v.5H2v1h3v-4H2v1zm1-9h1V4H2v1h1v3zm-1 3h1.8L2 13.1v.9h3v-1H3.2L5 10.9V10H2v1zm5-6v2h14V5H7zm0 14h14v-2H7v2zm0-6h14v-2H7v2z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleTaskList().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('taskList') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Task List"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11zm-6.5-1L9 14.5 10.5 13l2 2 4-4L17 12.5 11.5 18z"/>
                        </svg>
                      </button>
                    </div>

                    {/* Insert Elements */}
                    <div className="flex items-center space-x-1 pr-2 border-r border-gray-300">
                      <button
                        onClick={() => setShowLinkDialog(true)}
                        className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                        title="Insert Link"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => setShowImageDialog(true)}
                        className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                        title="Insert Image"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => setShowTableDialog(true)}
                        className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                        title="Insert Table"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M3 5v14h18V5H3zm8 12H5v-4h6v4zm0-6H5V7h6v4zm8 6h-6v-4h6v4zm0-6h-6V7h6v4zm4 6h-2v-4h2v4zm0-6h-2V7h2v4z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => setShowYoutubeDialog(true)}
                        className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                        title="Insert YouTube Video"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M10 16.5l6-4.5-6-4.5v9zM12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleBlockquote().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('blockquote') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Blockquote"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M6 17h3l2-4V7H5v6h3v4zm5 0h3l2-4V7h-6v6h3v4z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().setHorizontalRule().run()}
                        className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                        title="Horizontal Rule"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M19 13H5v-2h14v2z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().toggleCodeBlock().run()}
                        className={`p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center ${editor?.isActive('codeBlock') ? 'bg-gray-300 text-blue-600' : 'text-gray-700'}`}
                        title="Code Block"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/>
                        </svg>
                      </button>
                    </div>

                    {/* History */}
                    <div className="flex items-center space-x-1">
                      <button
                        onClick={() => editor?.chain().focus().undo().run()}
                        className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                        title="Undo"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M12.5 8c-2.65 0-5.05.99-6.9 2.6L2 7v9h9l-3.62-3.62c1.39-1.16 3.16-1.88 5.12-1.88 3.54 0 6.55 2.31 7.6 5.5l2.37-.78C21.08 11.03 17.15 8 12.5 8z"/>
                        </svg>
                      </button>
                      <button
                        onClick={() => editor?.chain().focus().redo().run()}
                        className="p-2 rounded hover:bg-gray-200 transition-colors flex items-center justify-center text-gray-700"
                        title="Redo"
                      >
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M18.4 10.6C16.55 8.99 14.15 8 11.5 8c-4.65 0-8.58 3.03-9.96 7.22L3.9 16c1.05-3.19 4.05-5.5 7.6-5.5 1.95 0 3.73.72 5.12 1.88L13 16h9V7l-3.6 3.6z"/>
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>
                
                {/* TipTap Editor */}
                <div className="border border-gray-300 rounded-b-lg bg-white overflow-hidden flex flex-col" style={{ height: 'calc(100vh - 350px)' }}>
                  <div className="flex-1 overflow-auto">
                    <EditorContent 
                      editor={editor}
                      className="prose prose-sm max-w-none focus:outline-none h-full"
                    />
                  </div>
                </div>
              </div>
            ) : (
              <textarea
                ref={editorRef}
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder={editorConfig.placeholder}
                className="w-full h-full p-3 pt-8 border border-gray-300 rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none overflow-auto"
                style={{ 
                  height: 'calc(100vh - 350px)',
                  maxHeight: 'calc(100vh - 300px)',
                  wordWrap: 'break-word',
                  whiteSpace: 'pre-wrap'
                }}
                spellCheck={false}
              />
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t space-y-3">
          {/* Version Note */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Version Note (Optional)
            </label>
            <input
              type="text"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Describe your changes..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {/* Error */}
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-md text-sm">
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-500">
              {(() => {
                const currentContent = isRichText && editor ? editor.getHTML() : content;
                return currentContent !== originalContent && (
                  <span className="text-orange-600">• Unsaved changes</span>
                );
              })()}
            </div>
            <div className="flex items-center space-x-3">
              <button
                onClick={handleClose}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || (() => {
                  const currentContent = isRichText && editor ? editor.getHTML() : content;
                  return currentContent === originalContent;
                })()}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
              >
                {saving && (
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                )}
                <span>{saving ? "Saving..." : "Save as New Version"}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Link Dialog */}
      {showLinkDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold mb-4">Add Link</h3>
            <input
              type="url"
              placeholder="https://example.com"
              value={linkUrl}
              onChange={(e) => setLinkUrl(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 mb-3"
            />
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowLinkDialog(false)}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddLink}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
              >
                Add Link
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Image Dialog */}
      {showImageDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold mb-4">Add Image</h3>
            <input
              type="url"
              placeholder="https://example.com/image.jpg"
              value={imageUrl}
              onChange={(e) => setImageUrl(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 mb-3"
            />
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowImageDialog(false)}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddImage}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
              >
                Add Image
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Table Dialog */}
      {showTableDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold mb-4">Insert Table</h3>
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Rows</label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={tableRows}
                  onChange={(e) => setTableRows(parseInt(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Columns</label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={tableCols}
                  onChange={(e) => setTableCols(parseInt(e.target.value))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowTableDialog(false)}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleInsertTable}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
              >
                Insert Table
              </button>
            </div>
          </div>
        </div>
      )}

      {/* YouTube Dialog */}
      {showYoutubeDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold mb-4">Add YouTube Video</h3>
            <input
              type="url"
              placeholder="https://www.youtube.com/watch?v=..."
              value={youtubeUrl}
              onChange={(e) => setYoutubeUrl(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 mb-3"
            />
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowYoutubeDialog(false)}
                className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddYouTube}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
              >
                Add Video
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}