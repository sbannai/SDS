// Common Types for the Document Management System

export interface User {
  id: number;
  name: string;
  email: string;
  role: 'ADMIN' | 'STAFF' | 'TEACHER';
  department?: string;
}

export interface Document {
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
  upload_note?: string;
  version_number?: number;
}

export interface Folder {
  id: number;
  name: string;
  icon?: string;
  documentCount?: number;
}

export interface UploadResponse {
  document?: Document;
  version?: {
    id: number;
    document_id: number;
    version_number: number;
    filepath: string;
    upload_note?: string;
    created_at: string;
  };
  downloadUrl?: string;
  documentId?: number;
  versionId?: number;
  versionNumber?: number;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
}