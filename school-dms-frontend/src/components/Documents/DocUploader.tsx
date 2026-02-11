// src/components/Documents/DocUploader.tsx
import React, { useState, useRef, DragEvent } from "react";

type Props = {
  documentId?: number | null;
  folderId?: number | null;
  onUploaded?: (resp: any) => void;
};

const API = (import.meta.env.VITE_API_URL as string) || "http://localhost:4000";

export default function DocUploader({ documentId = null, folderId = null, onUploaded }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // show returned link + version
  const [uploadedUrl, setUploadedUrl] = useState<string>("");
  const [uploadedVersion, setUploadedVersion] = useState<string>("");
  
  const dragCounter = useRef(0);

  function handleFile(f: File | null) {
    if (!f) {
      setFile(null);
      setTitle("");
      return;
    }

    // file type check - accept all document types except executables
    const disallowedTypes = [
      'application/x-msdownload', // .exe
      'application/x-msdos-program',
      'application/x-executable',
      'application/x-msi',
      'application/x-sh',
      'application/x-bat',
      'application/x-cmd'
    ];
    
    if (disallowedTypes.includes(f.type)) {
      setErr("Executable files are not allowed");
      setFile(null);
      setTitle("");
      return;
    }

    // size limit: 200 MB
    if (f.size > 200 * 1024 * 1024) {
      setErr("File is too large (max 200 MB)");
      setFile(null);
      setTitle("");
      return;
    }

    setErr(null);
    setFile(f);

    // auto-set title from filename (without extension)
    const base = f.name.replace(/\.[^/.]+$/, "");
    setTitle(base);
  }

  function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files && e.target.files[0];
    handleFile(f);
  }

  const handleDragEnter = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current++;
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) {
      setIsDragging(false);
    }
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    dragCounter.current = 0;

    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    handleFile(f);
  };

  async function upload(e?: React.FormEvent) {
    if (e) e.preventDefault();
    if (!file) return setErr("Choose a file first");
    setLoading(true);
    setErr(null);

    try {
      const token = localStorage.getItem("token");
      const form = new FormData();
      form.append("file", file);
      if (title) form.append("title", title);
      if (note) form.append("uploadNote", note);
      if (documentId) form.append("documentId", String(documentId));
      form.append("folderId", String(folderId || 1)); // Default to folder 1 if none selected

      console.log("Uploading with token:", token ? "present" : "missing");
      console.log("FormData entries:");
      for (let [key, value] of form.entries()) {
        console.log(key, value);
      }

      const res = await fetch(`${API}/api/documents/upload`, {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        body: form
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ message: res.statusText }));
        console.error("Upload failed:", body);
        throw new Error(body.message || "Upload failed");
    }

      const data = await res.json();

    // Clear selected file / inputs
    setFile(null);
    setNote("");
    setTitle("");

    // Call parent callback
    if (onUploaded) onUploaded(data);

    // Determine returned download URL (server returns downloadUrl in both upload and version flows)
    const dl = data.downloadUrl ?? (data.version && data.version.filepath) ?? (data.document && data.document.filepath) ?? null;
    const verNum = data.versionNumber ?? (data.version && data.version.version_number) ?? null;

    if (dl) {
      setUploadedUrl(dl);
      // automatically open the file in a new tab
      try {
        window.open(dl, "_blank");
      } catch (e) {
        // ignore popup blockers
      }
    }

    if (verNum) {
      setUploadedVersion(String(verNum));
        alert("Uploaded: v" + verNum);
      } else {
        alert("Uploaded");
    }
    } catch (err: any) {
      setErr(err.message || "Upload error");
    } finally {
      setLoading(false);
    }
  }

return (
    <div className="space-y-4">
      <form onSubmit={upload} className="space-y-6">
        {/* File Upload Area */}
        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-2">
            Select Document
          </label>
          <div
            className={`
              relative border-2 border-dashed rounded-lg transition-all duration-200
              ${isDragging 
                ? 'border-primary-500 bg-primary-50' 
                : 'border-neutral-300 bg-neutral-50 hover:border-neutral-400'
              }
            `}
            onDragEnter={handleDragEnter}
            onDragLeave={handleDragLeave}
            onDragOver={handleDragOver}
            onDrop={handleDrop}
          >
            <input
              type="file"
              accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.rtf,.odt,.ods,.odp,.csv,.json,.xml,.html,.htm,.md"
              onChange={onFileChange}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
              {isDragging ? (
                <>
                  <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mb-4">
                    <svg className="w-8 h-8 text-primary-600 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <p className="text-lg font-medium text-primary-700 mb-2">Drop your document here</p>
                  <p className="text-sm text-primary-600">Release to upload</p>
                </>
              ) : (
                <>
                  <div className="w-16 h-16 bg-neutral-100 rounded-full flex items-center justify-center mb-4">
                    <svg className="w-8 h-8 text-neutral-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <p className="text-lg font-medium text-neutral-700 mb-2">
                    {file ? file.name : 'Drop your document here or click to browse'}
                  </p>
                  <p className="text-sm text-neutral-500">
                    {file ? 'Click to change file' : 'Maximum file size: 200MB'}
                  </p>
                </>
              )}
            </div>
          </div>
<p className="mt-2 text-xs text-neutral-500 text-center">
             Supported formats: PDF, Word, Excel, PowerPoint, Text, and more
           </p>
        </div>

        {/* File Info Display */}
        {title && (
          <div className="bg-blue-50 border-2 border-blue-200 rounded-xl p-4 animate-fade-in">
            <div className="flex items-start space-x-4">
              <div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center flex-shrink-0">
                <svg className="w-6 h-6 text-blue-600" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z" />
                </svg>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-blue-900 mb-1">File Selected</p>
                <p className="text-sm font-medium text-blue-700 truncate mb-1">{title}</p>
                {file && (
                  <div className="flex items-center space-x-4 text-xs text-blue-600">
                    <span>Size: {(file.size / 1024 / 1024).toFixed(2)} MB</span>
                    <span>•</span>
                    <span>Type: {file.type || 'Unknown'}</span>
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => {
                  setFile(null);
                  setTitle("");
                  setErr(null);
                }}
                className="text-blue-600 hover:text-blue-800 transition-colors p-1"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
        )}

        {/* Note Input */}
        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-2">
            Upload Note (Optional)
          </label>
          <input
            type="text"
            placeholder="Add a note for this upload..."
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="w-full px-4 py-3 border border-neutral-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          />
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={loading || !file}
          className="w-full flex items-center justify-center space-x-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
        >
          {loading && (
            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
          )}
          <span>{loading ? "Uploading..." : (documentId ? "Upload New Version" : "Upload Document")}</span>
        </button>

        {/* Error Display */}
        {err && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center space-x-2">
            <span className="text-red-500">⚠</span>
            <span className="text-sm">{err}</span>
          </div>
        )}

        {/* Success Messages */}
        {uploadedVersion && (
          <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg flex items-center space-x-2">
            <span className="text-green-500">✓</span>
            <span className="text-sm">Successfully uploaded version v{uploadedVersion}</span>
          </div>
        )}

        {uploadedUrl && (
          <div className="bg-blue-50 border border-blue-200 text-blue-700 px-4 py-3 rounded-lg">
            <p className="text-sm font-medium mb-2">Upload completed</p>
            <a 
              href={uploadedUrl} 
              target="_blank" 
              rel="noreferrer"
              className="inline-flex items-center space-x-1 text-blue-600 hover:text-blue-800 text-sm font-medium"
            >
              <span>Open uploaded file</span>
              <span>→</span>
            </a>
          </div>
        )}
      </form>
    </div>
  );
}
