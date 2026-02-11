// src/components/Documents/EditModeInfo.tsx
import React from "react";

type Props = {
  isOpen: boolean;
  onClose: () => void;
};

export default function EditModeInfo({ isOpen, onClose }: Props) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Document Editing Guide</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-6">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h3 className="text-lg font-medium text-blue-900 mb-2">🎯 New Editing Workflow</h3>
            <p className="text-blue-700">
              We've introduced two types of editing for your convenience:
            </p>
          </div>

          <div className="space-y-4">
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <h4 className="font-medium text-purple-900 mb-2 flex items-center">
                <span className="mr-2">🖥️</span>
                Native Application Editing
              </h4>
              <div className="text-sm text-purple-700 space-y-2">
                <p><strong>Documents:</strong> Word (.docx), Excel (.xlsx), PowerPoint (.pptx)</p>
                <p><strong>What happens:</strong> Opens in your installed Microsoft Office or equivalent application</p>
                <p><strong>Button:</strong> <span className="text-purple-600 font-medium">"Open in Microsoft Word/Excel/PowerPoint"</span></p>
                <p><strong>Workflow:</strong> Edit → Save file → Upload as new version</p>
              </div>
            </div>

            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
              <h4 className="font-medium text-orange-900 mb-2 flex items-center">
                <span className="mr-2">✏️</span>
                In-Application Editing
              </h4>
              <div className="text-sm text-orange-700 space-y-2">
                <p><strong>Documents:</strong> Text files, Markdown, JSON, HTML, CSS, JS, XML, YAML, CSV</p>
                <p><strong>What happens:</strong> Opens directly in browser editor</p>
                <p><strong>Button:</strong> <span className="text-orange-600 font-medium">"Edit"</span></p>
                <p><strong>Workflow:</strong> Edit → Ctrl+S to save → Automatic version creation</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
            <h4 className="font-medium text-gray-900 mb-2">📋 Example Scenarios</h4>
            <div className="text-sm text-gray-700 space-y-2">
              <div className="flex items-start">
                <span className="text-purple-600 mr-2">•</span>
                <div>
                  <strong>Word document (.docx):</strong> Click "Open in Microsoft Word" → Edit in Word → Save file → Upload new version
                </div>
              </div>
              <div className="flex items-start">
                <span className="text-orange-600 mr-2">•</span>
                <div>
                  <strong>Text file (.txt):</strong> Click "Edit" → Edit in browser → Press Ctrl+S → Automatic version
                </div>
              </div>
              <div className="flex items-start">
                <span className="text-purple-600 mr-2">•</span>
                <div>
                  <strong>Excel spreadsheet (.xlsx):</strong> Click "Open in Microsoft Excel" → Edit data → Save file → Upload new version
                </div>
              </div>
            </div>
          </div>

          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h4 className="font-medium text-green-900 mb-2 flex items-center">
              <span className="mr-2">🔄</span>
              Version History
            </h4>
            <p className="text-sm text-green-700">
              <strong>All edits are tracked!</strong> Whether you use native applications or in-app editing, every new version appears in Version History with proper metadata and timestamps.
            </p>
          </div>
        </div>

        <div className="mt-6 flex justify-end">
          <button
            onClick={onClose}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors"
          >
            Got it, thanks!
          </button>
        </div>
      </div>
    </div>
  );
}