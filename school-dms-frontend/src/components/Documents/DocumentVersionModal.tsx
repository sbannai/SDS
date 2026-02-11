// src/components/Documents/DocumentVersionModal.tsx
import React, { useEffect, useState } from "react";
import axiosClient from "../../api/axiosClient";

type Version = {
  id: number;
  version_number: number;
  filename: string;
  filepath?: string;
  mime_type?: string;
  file_size?: number;
  version_note?: string;
  created_by?: number;
  created_by_name?: string;
  created_at?: string;
};

type Props = {
  documentId: number;
  documentTitle: string;
  isOpen: boolean;
  onClose: () => void;
};

export default function DocumentVersionModal({ documentId, documentTitle, isOpen, onClose }: Props) {
  const [versions, setVersions] = useState<Version[]>([]);
  const [loading, setLoading] = useState(false);

  async function loadVersions() {
    setLoading(true);
    try {
      const res = await axiosClient.get(`/documents/${documentId}/versions`);
      setVersions(res.data);
    } catch (err: any) {
      console.error("load versions error", err.response?.data || err.message);
      alert(err.response?.data?.message || "Failed to load versions");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (isOpen && documentId) {
      loadVersions();
    }
  }, [isOpen, documentId]);

  const handleDownload = (versionId: number, filename: string) => {
    axiosClient
      .get(`/documents/version/${versionId}/download`, { responseType: "blob" })
      .then((res) => {
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const a = document.createElement("a");
        a.href = url;
        a.setAttribute("download", filename);
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      })
      .catch((err) => {
        console.error("download error", err.response?.data || err.message);
        alert(err.response?.data?.message || "Download failed");
      });
  };

  const formatFileSize = (bytes: number | undefined) => {
    if (!bytes) return "-";
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + " " + sizes[i];
  };

  const formatDate = (dateString: string | undefined) => {
    if (!dateString) return "-";
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-4xl max-h-[80vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Document Versions</h2>
            <p className="text-sm text-gray-500 mt-1">{documentTitle}</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[60vh]">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <div className="w-8 h-8 border-2 border-blue-200 border-t-blue-600 rounded-full animate-spin mx-auto mb-4"></div>
                <p className="text-gray-500">Loading versions...</p>
              </div>
            </div>
          ) : versions.length === 0 ? (
            <div className="text-center py-12">
              <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-gray-400 text-2xl">📄</span>
              </div>
              <h4 className="text-lg font-medium text-gray-900 mb-2">No versions found</h4>
              <p className="text-gray-500">This document doesn't have any version history yet.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {versions.map((version, index) => (
                <div
                  key={version.id}
                  className={`border rounded-lg p-4 transition-all ${
                    index === 0 ? 'border-blue-300 bg-blue-50' : 'border-gray-200 bg-white'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          index === 0 ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'
                        }`}>
                          Version {version.version_number}
                          {index === 0 && ' (Current)'}
                        </span>
                        <span className="text-sm text-gray-500">
                          {formatDate(version.created_at)}
                        </span>
                      </div>
                      
                      <div className="mb-2">
                        <p className="text-sm font-medium text-gray-900">{version.filename}</p>
                        <p className="text-xs text-gray-500">
                          Uploaded by {version.created_by_name || 'Unknown'} • {formatFileSize(version.file_size)}
                        </p>
                      </div>

                      {version.version_note && (
                        <div className="mb-3">
                          <div className={`text-xs rounded p-2 ${
                            version.version_note.includes('Document edited') 
                              ? 'bg-orange-50 text-orange-700 border border-orange-200' 
                              : 'bg-gray-50 text-gray-600'
                          }`}>
                            <span className="font-medium">
                              {version.version_note.includes('Document edited') ? '📝 Edited:' : '📝 Note:'}
                            </span> {version.version_note}
                          </div>
                        </div>
                      )}

                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleDownload(version.id, version.filename)}
                          className="inline-flex items-center px-3 py-1.5 bg-blue-50 text-blue-700 text-sm font-medium rounded-md hover:bg-blue-100 transition-colors"
                        >
                          <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                          </svg>
                          Download
                        </button>
                        
                        {version.filepath && (
                          <button
                            onClick={() => window.open(version.filepath, '_blank')}
                            className="inline-flex items-center px-3 py-1.5 bg-green-50 text-green-700 text-sm font-medium rounded-md hover:bg-green-100 transition-colors"
                          >
                            <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                            </svg>
                            Open
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-200 bg-gray-50">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Total {versions.length} version{versions.length !== 1 ? 's' : ''}
            </p>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}