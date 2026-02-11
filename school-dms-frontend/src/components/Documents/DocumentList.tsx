// src/components/Documents/DocumentList.tsx
import React, { useEffect, useState, useCallback } from "react";
import DocumentVersionModal from "./DocumentVersionModal";
import DocumentEditor from "./DocumentEditor";
import EditModeInfo from "./EditModeInfo";


type Doc = {
  id: number;
  folder_id?: number;
  title: string;
  filename: string;
  filepath?: string;
  mime_type?: string;
  file_size?: number;
  owner_id?: number;
  uploaded_at?: string;
  updated_at?: string;
};

type Props = {
  folderId: number | null;
};

const API = (import.meta.env.VITE_API_URL as string) || "http://localhost:4000";

export default function DocumentList({ folderId }: Props) {
  const [docs, setDocs] = useState<Doc[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedDocument, setSelectedDocument] = useState<{id: number, title: string} | null>(null);
  const [isVersionModalOpen, setIsVersionModalOpen] = useState(false);
  const [editingDocument, setEditingDocument] = useState<Doc | null>(null);
  const [showEditInfo, setShowEditInfo] = useState(false);

  

  // Extracted loader so we can call it after upload
  const loadDocs = useCallback(async () => {
    console.log("Loading documents for folderId:", folderId);
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        console.log("No token found");
        setDocs([]);
        setLoading(false);
        return;
      }
      
      const q = folderId ? `?folderId=${folderId}` : "";
      console.log("Fetching:", `${API}/api/documents${q}`);
      const res = await fetch(`${API}/api/documents${q}`, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: res.statusText }));
        console.error("Fetch error:", err);
        throw new Error(err.message || "Failed to fetch");
      }
      const data = await res.json();
      console.log("Documents received:", data);
      setDocs(Array.isArray(data) ? data : []);
    } catch (e: any) {
      console.error("Load documents error:", e);
      setError(e.message || "Unknown error");
      setDocs([]);
    } finally {
      setLoading(false);
    }
  }, [folderId]);

  useEffect(() => {
    loadDocs();
  }, [loadDocs]);

  

// Check if document is editable (non-PDF and text-based)
  const isEditable = (doc: Doc) => {
    // Always hide edit button for PDF files
    if (doc.mime_type === "application/pdf") return false;
    
    // If no MIME type, check file extension as fallback
    if (!doc.mime_type) {
      const filename = (doc.filename || '').toLowerCase();
      const editableExtensions = [
        '.txt', '.md', '.json', '.html', '.htm', '.css', '.js', '.xml', '.yaml', '.yml', '.csv',
        '.docx', '.xlsx', '.pptx' // Office documents
      ];
      return editableExtensions.some(ext => filename.endsWith(ext));
    }
    
    // List of text-based MIME types that can be edited
    const editableTypes = [
      "text/plain",
      "text/html",
      "text/css",
      "text/javascript",
      "text/markdown",
      "text/csv",
      "text/xml",
      "text/yaml",
      "application/json",
      "application/javascript",
      "application/xml",
      "application/x-yaml",
      // Office document formats
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
      "application/vnd.openxmlformats-officedocument.presentationml.presentation", // .pptx
    ];
    
    return editableTypes.includes(doc.mime_type);
  };

  // Get file icon based on MIME type
  const getFileIcon = (doc: Doc) => {
    if (!doc.mime_type) return "📄";
    
    const iconMap: { [key: string]: string } = {
      "application/pdf": "📄",
      "text/plain": "📝",
      "text/html": "🌐",
      "text/css": "🎨",
      "text/javascript": "⚡",
      "application/javascript": "⚡",
      "application/json": "📋",
      "text/markdown": "📝",
      "text/csv": "📊",
      "text/xml": "📄",
      "application/xml": "📄",
      "text/yaml": "⚙️",
      "application/x-yaml": "⚙️",
      // Office document icons
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "📝",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "📊",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation": "📽️",
    };

    return iconMap[doc.mime_type] || "📄";
  };

  // Check if document should open in native app (only PDF files should not be edited)
  const openInNativeApp = (doc: Doc) => {
    if (!doc.mime_type) return false;
    
    // Only PDF files should not be edited directly
    const pdfTypes = [
      "application/pdf",
    ];
    
    // If it's a PDF file, don't open in web editor
    if (pdfTypes.includes(doc.mime_type)) {
      return true; // PDF files should open in native app (or not at all)
    }
    
    // ALL other files should open in web editor
    // This includes: .txt, .docx, .xlsx, .pptx, .doc, .xls, .ppt, images, etc.
    return false;
  };

  // Get application name for file type
  const getAppName = (mimeType?: string) => {
    if (!mimeType) return "Application";
    
    const appMap: { [key: string]: string } = {
      // Microsoft Office formats
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Microsoft Word",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Microsoft Excel",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation": "Microsoft PowerPoint",
      "application/msword": "Microsoft Word",
      "application/vnd.ms-excel": "Microsoft Excel", 
      "application/vnd.ms-powerpoint": "Microsoft PowerPoint",
      
      // Image formats
      "image/jpeg": "Image Viewer",
      "image/jpg": "Image Viewer",
      "image/png": "Image Viewer",
      "image/gif": "Image Viewer",
      "image/bmp": "Image Viewer",
      "image/webp": "Image Viewer",
      "image/svg+xml": "Image Viewer",
      
      // Audio/Video formats
      "audio/mp3": "Media Player",
      "audio/mpeg": "Media Player",
      "audio/wav": "Media Player",
      "video/mp4": "Video Player",
      "video/avi": "Video Player",
      "video/mov": "Video Player",
      
      // Archive formats
      "application/zip": "Archive Manager",
      "application/x-rar-compressed": "Archive Manager",
      "application/x-7z-compressed": "Archive Manager",
      
      // Other formats
      "application/octet-stream": "Default Application",
    };
    
    return appMap[mimeType] || "Default Application";
  };

// Handle document edit - open in native app or web editor
  const handleEdit = async (doc: Doc) => {
    // Check if we should open in native app
    const shouldOpenNative = openInNativeApp(doc);
    
    if (shouldOpenNative) {
      // Open in native application
      try {
        const token = localStorage.getItem("token");
        const res = await fetch(`${API}/api/documents/${doc.id}/download`, {
          headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        });

        if (res.ok) {
          // Get the blob directly from response
          const blob = await res.blob();
          
          // Create a blob URL with proper MIME type
          const blobUrl = window.URL.createObjectURL(blob);
          
          // Try multiple approaches to open the file
          
          // Method 1: Try to open directly with window.open (may trigger system handler)
          try {
            window.open(blobUrl, '_blank');
          } catch (err) {
            console.log('Window.open failed, trying download method');
          }
          
          // Method 2: Also create download link as fallback
          const link = window.document.createElement('a');
          link.href = blobUrl;
          link.download = doc.filename;
          link.style.display = 'none';
          window.document.body.appendChild(link);
          
          // Delay the click to ensure blob is ready
          setTimeout(() => {
            try {
              link.click();
            } catch (clickError) {
              console.log('Click failed, trying window.open fallback');
              window.open(blobUrl, '_blank');
            }
            
            // Clean up DOM
            try {
              if (window.document.body.contains(link)) {
                window.document.body.removeChild(link);
              }
            } catch (removeError) {
              console.warn('Failed to remove link from DOM:', removeError);
            }
          }, 500);
          
          // Clean up blob URL after delay
          setTimeout(() => {
            try {
              window.URL.revokeObjectURL(blobUrl);
            } catch (revokeError) {
              console.warn('Failed to revoke blob URL:', revokeError);
            }
          }, 10000);
          
          // Show helpful message about next steps
          setTimeout(() => {
            const fileExtension = doc.filename.split('.').pop()?.toLowerCase();
            const isHtml = fileExtension === 'html' || fileExtension === 'htm';
            
            let instructions = `${getAppName(doc.mime_type)} - Download Complete!\n\n📋 How to open:\n\n`;
            
            if (isHtml) {
              instructions += `🌐 HTML File Instructions:\n`;
              instructions += `• Double-click to open in any web browser (Chrome, Firefox, Safari, etc.)\n`;
              instructions += `• Or right-click → "Open with" → Choose your preferred browser\n\n`;
              instructions += `📝 Editing Options:\n`;
              instructions += `• Browser: Open in browser, then use developer tools or view source\n`;
              instructions += `• Text Editor: Open with VS Code, Notepad++, Sublime Text, etc.\n`;
              instructions += `• Web Editor: Upload back to the system for rich text editing\n`;
            } else {
              instructions += `🔍 OPTION 1: Look in your Downloads folder for "${doc.filename}" and double-click it\n\n`;
              instructions += `🔍 OPTION 2: If file didn't auto-open, right-click the downloaded file → "Open with" → Choose ${getAppName(doc.mime_type)}\n`;
            }
            
            instructions += `\n📋 After editing:\n1. Save your changes\n2. Upload the updated file using the "Upload New Version" button\n\n✅ This will create a new version in the document history`;
            
            alert(instructions);
          }, 1000);
        }
      } catch (err: any) {
        console.error("Failed to open document:", err);
        alert("Failed to open document: " + err.message);
      }
    } else {
      // Open in web editor
      setEditingDocument(doc);
    }
  };

  // Handle save edited document
  const handleSaveEdit = async (content: string, note: string) => {
    if (!editingDocument) return;

    try {
      const token = localStorage.getItem("token");
      
      // Determine the appropriate format based on document type
      let saveFormat = "text";
      let processedContent = content;
      
      // Check if content contains HTML (rich text)
      if (content.includes('<') && content.includes('>')) {
        // For HTML content, save as HTML format for better compatibility
        saveFormat = "html";
        processedContent = content; // Keep HTML content
      } else {
        // For plain text, save as text format
        saveFormat = "text";
        processedContent = content;
      }
      
      const res = await fetch(`${API}/api/documents/${editingDocument.id}/edit`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token && { Authorization: `Bearer ${token}` }),
        },
        body: JSON.stringify({ content: processedContent, note, format: saveFormat }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ message: res.statusText }));
        throw new Error(body.message || "Failed to save document");
      }

      const data = await res.json();
      console.log("Document saved as new version:", data);
      
      // Refresh documents list
      await loadDocs();
      
      // Close editor
      setEditingDocument(null);
      
      // Show success message with format information
      alert(`Document saved successfully as new version! (${saveFormat.toUpperCase()} format)`);
    } catch (err: any) {
      console.error("Save error:", err);
      throw new Error(err.message || "Failed to save document");
    }
  };

  // Download via backend (adds Authorization header) and then open the redirected presigned URL
  const handleDownload = async (docId: number) => {
    try {
      const token = localStorage.getItem("token");
      const res = await fetch(`${API}/api/documents/${docId}/download`, {
        method: "GET",
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        // let fetch follow redirects so res.url becomes the final presigned URL
        redirect: "follow",
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({ message: res.statusText }));
        throw new Error(body.message || "Download failed");
      }
      // res.url should be the final URL after redirection
      const finalUrl = res.url;
      if (!finalUrl) throw new Error("No download URL returned");
      window.open(finalUrl, "_blank");
    } catch (err: any) {
      alert("Download failed: " + (err.message || err));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <div className="modern-spinner mx-auto mb-4"></div>
          <p className="text-neutral-500">Loading documents...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <div className="w-16 h-16 bg-red-50 rounded-full flex items-center justify-center mx-auto mb-4">
            <span className="text-red-600">⚠</span>
          </div>
          <h4 className="text-lg font-medium text-red-900 mb-2">Error Loading Documents</h4>
          <p className="text-red-600">{error}</p>
        </div>
      </div>
    );
  }

const formatFileSize = (bytes: number | undefined) => {
    if (!bytes) return "-";
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + " " + sizes[i];
  };



  return (
    <div className="space-y-6">
      

      {/* Documents List */}
      <div className="modern-card">
        <div className="card-header flex items-center justify-between px-6 py-4">
          <div>
            <h3 className="text-lg font-semibold text-neutral-900">Documents</h3>
            <p className="text-sm text-neutral-500">{docs.length} documents found</p>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowEditInfo(true)}
              className="inline-flex items-center px-3 py-1 bg-blue-50 text-blue-700 text-sm font-medium rounded-md hover:bg-blue-100 transition-colors whitespace-nowrap"
              title="Learn about new editing features"
            >
              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Editing Guide
            </button>
            <div className="px-3 py-1 bg-primary-100 text-primary-700 rounded-full text-sm font-medium">
              {folderId ? `Category ${folderId}` : 'All Categories'}
            </div>
          </div>
        </div>
        
        <div className="card-body p-0">
          {docs.length === 0 ? (
            <div className="text-center py-16 px-6">
              <div className="w-20 h-20 bg-neutral-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-3xl text-neutral-400">📄</span>
              </div>
              <h4 className="text-xl font-semibold text-neutral-900 mb-3">No documents found</h4>
              <p className="text-neutral-500 max-w-md mx-auto">Upload your first document to get started with the document management system.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-neutral-200 bg-neutral-50">
                    <th className="text-left px-6 py-3 text-xs font-semibold text-neutral-700 uppercase tracking-wider">Document</th>
                    <th className="text-left px-6 py-3 text-xs font-semibold text-neutral-700 uppercase tracking-wider">Size</th>
                    <th className="text-right px-6 py-3 text-xs font-semibold text-neutral-700 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-200">
                  {docs.map((d) => {
                    const editable = isEditable(d);
                    return (
                    <tr key={d.id} className="hover:bg-neutral-50 transition-colors align-middle">
                      <td className="px-6 py-4">
                        <div className="flex items-center space-x-3">
                          <div className="w-10 h-10 bg-red-50 rounded-lg flex items-center justify-center flex-shrink-0">
                            <span className="text-red-600 text-sm">{getFileIcon(d)}</span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-neutral-900 truncate">
                              {d.title || d.filename}
                            </p>
                            <p className="text-xs text-neutral-500 truncate">
                              {d.filename}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-neutral-600 inline-block">{formatFileSize(d.file_size)}</span>
                      </td>
<td className="px-6 py-4">
                          <div className="flex items-center justify-end space-x-2 gap-2">
                            {editable && (
                              <>
                                {openInNativeApp(d) ? (
                                  <button
                                    onClick={() => handleEdit(d)}
                                    className="inline-flex items-center px-3 py-1.5 bg-purple-50 text-purple-700 text-sm font-medium rounded-md hover:bg-purple-100 transition-colors whitespace-nowrap"
                                  >
                                    <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                                    </svg>
                                    Open in {getAppName(d.mime_type)}
                                  </button>
                                ) : (
                                  <button
                                    onClick={() => handleEdit(d)}
                                    className="inline-flex items-center px-3 py-1.5 bg-orange-50 text-orange-700 text-sm font-medium rounded-md hover:bg-orange-100 transition-colors whitespace-nowrap"
                                  >
                                    <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                    </svg>
                                    Edit
                                  </button>
                                )}
                              </>
                            )}
                            <button
                              onClick={() => {
                                setSelectedDocument({id: d.id, title: d.title || d.filename});
                                setIsVersionModalOpen(true);
                              }}
                              className="inline-flex items-center px-3 py-1.5 bg-purple-50 text-purple-700 text-sm font-medium rounded-md hover:bg-purple-100 transition-colors whitespace-nowrap"
                            >
                              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              Version History
                            </button>
                            <button
                              onClick={() => handleDownload(d.id)}
                              className="inline-flex items-center px-3 py-1.5 bg-blue-50 text-blue-700 text-sm font-medium rounded-md hover:bg-blue-100 transition-colors whitespace-nowrap"
                            >
                              Download
                            </button>
<button
                             onClick={async () => {
                               const input = document.createElement("input");
                               input.type = "file";
                               
                               // Set appropriate accept based on document type
                               if (d.mime_type && d.mime_type.includes("openxmlformats")) {
                                 input.accept = ".docx,.xlsx,.pptx";
                               } else if (d.mime_type && d.mime_type.includes("ms-")) {
                                 input.accept = ".doc,.xls,.ppt";
                               } else {
                                 input.accept = ".pdf,.txt,.md,.json,.html,.css,.js,.xml,.yaml,.csv";
                               }
                               
                               input.onchange = async () => {
                                const file = input.files && input.files[0];
                                if (!file) return;
                                try {
                                  const token = localStorage.getItem("token");
                                  const form = new FormData();
                                  form.append("file", file);
                                  form.append("documentId", String(d.id));
                                  const res = await fetch(`${API}/api/documents/upload`, {
                                    method: "POST",
                                    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
                                    body: form,
                                  });
                                  if (!res.ok) {
                                    const body = await res.json().catch(() => ({ message: res.statusText }));
                                    throw new Error(body.message || "Upload failed");
                                  }
                                  loadDocs();
                                } catch (err: any) {
                                  alert("Upload failed: " + (err.message || err));
                                }
                              };
                              input.click();
                            }}
                            className="inline-flex items-center px-1 py-1.5 bg-green-50 text-green-700 text-sm font-medium rounded-md hover:bg-green-100 transition-colors  whitespace-nowrap"
                          >
                            Upload New Version
                          </button>
</div>
                       </td>
                     </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
</div>
       </div>

{/* Version History Modal */}
        {selectedDocument && (
          <DocumentVersionModal
            documentId={selectedDocument.id}
            documentTitle={selectedDocument.title}
            isOpen={isVersionModalOpen}
            onClose={() => {
              setIsVersionModalOpen(false);
              setSelectedDocument(null);
            }}
          />
        )}

        {/* Document Editor Modal */}
        {editingDocument && (
          <DocumentEditor
            document={editingDocument}
            onClose={() => setEditingDocument(null)}
            onSave={handleSaveEdit}
          />
        )}

        {/* Edit Mode Info Modal */}
        {showEditInfo && (
          <EditModeInfo
            isOpen={showEditInfo}
            onClose={() => setShowEditInfo(false)}
          />
        )}
     </div>
   );
 }
