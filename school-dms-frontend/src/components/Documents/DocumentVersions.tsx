// src/components/Documents/DocumentVersions.tsx
import React, { useEffect, useState } from "react";
import axiosClient from "../../api/axiosClient";

type Version = {
  id: number;
  filename: string;
  mime_type?: string;
  file_size?: number;
  version_note?: string;
  created_by?: number;
  created_by_name?: string;
  created_at?: string;
};

export default function DocumentVersions({ documentId }: { documentId: number }) {
  const [versions, setVersions] = useState<Version[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);

  async function loadVersions() {
    try {
      const res = await axiosClient.get(`/documents/${documentId}/versions`);
      setVersions(res.data);
    } catch (err: any) {
      console.error("load versions error", err.response?.data || err.message);
      alert(err.response?.data?.message || "Failed to load versions");
    }
  }

  useEffect(() => {
    loadVersions();
  }, [documentId]);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return alert("Choose file");
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("version_note", note);
      const res = await axiosClient.post(`/documents/${documentId}/upload-version`, fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      alert(res.data?.message || "Uploaded");
      setFile(null);
      setNote("");
      await loadVersions();
    } catch (err: any) {
      console.error("upload error", err.response?.data || err.message);
      alert(err.response?.data?.message || "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (versionId: number) => {
    // simple download link — will require auth header; open in same tab to use cookies? We'll use axios to fetch blob
    axiosClient
      .get(`/documents/version/${versionId}/download`, { responseType: "blob" })
      .then((res) => {
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const a = document.createElement("a");
        const contentDisposition = res.headers["content-disposition"];
        // if filename available in header parse, else fallback
        a.href = url;
        a.setAttribute("download", `version-${versionId}`);
        document.body.appendChild(a);
        a.click();
        a.remove();
      })
      .catch((err) => {
        console.error("download error", err.response?.data || err.message);
        alert(err.response?.data?.message || "Download failed");
      });
  };

  return (
    <div style={{ padding: 12 }}>
      <h3>Document Versions</h3>

      <form onSubmit={handleUpload} style={{ marginBottom: 12 }}>
        <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        <input
          type="text"
          placeholder="version note (optional)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          style={{ marginLeft: 8 }}
        />
        <button type="submit" disabled={loading} style={{ marginLeft: 8 }}>
          {loading ? "Uploading..." : "Upload new version"}
        </button>
      </form>

      <ul>
        {versions.length === 0 && <li>No versions yet</li>}
        {versions.map((v) => (
          <li key={v.id} style={{ marginBottom: 8 }}>
            <strong>{v.filename}</strong> — {v.created_by_name ?? "Unknown"} — {new Date(v.created_at || "").toLocaleString()}
            <div>
              <button onClick={() => handleDownload(v.id)} style={{ marginRight: 8 }}>
                Download
              </button>
            </div>
            {v.version_note && <div style={{ color: "#666" }}>{v.version_note}</div>}
          </li>
        ))}
      </ul>
    </div>
  );
}
