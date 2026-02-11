import Sidebar from "../components/Layout/Sidebar";
import DocumentList from "../components/Documents/DocumentList";
import DocUploader from "../components/Documents/DocUploader";
import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

const API = (import.meta.env.VITE_API_URL as string) || "http://localhost:4000";

export default function DashboardPage() {
  const { user } = useAuth();
  const [activeFolderId, setActiveFolderId] = useState<number | null>(null);
  const [totalDocuments, setTotalDocuments] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshKey, setRefreshKey] = useState(0);
  
// Check if user is administrator
  const isAdmin = user?.role?.toUpperCase() === 'ADMIN';
  
  // Fetch actual document count from database
  useEffect(() => {
    const fetchDocumentCount = async () => {
      try {
        const token = localStorage.getItem("token");
        
        if (!token) {
          setTotalDocuments(0);
          setLoading(false);
          return;
        }

        const res = await fetch(`${API}/api/documents/count`, {
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
        });

        if (res.ok) {
          const data = await res.json();
          setTotalDocuments(data.count || 0);
        } else {
          console.error("Failed to fetch document count");
          setTotalDocuments(0);
        }
      } catch (error) {
        console.error("Error fetching document count:", error);
        setTotalDocuments(0);
      } finally {
        setLoading(false);
      }
    };

    fetchDocumentCount();
  }, [API]);

  const getCategoryName = (folderId: number | null) => {
    const categories: Record<number, string> = {
      1: "Administration",
      2: "Staff Records",
      3: "Student Records",
      4: "Academics",
      5: "Examinations"
    };
    return folderId ? categories[folderId] || "Unknown" : "All Categories";
  };

  return (
    <div className="min-h-screen bg-neutral-50">
      <Sidebar activeFolderId={activeFolderId} onSelectFolder={setActiveFolderId} />
      
      <main className="ml-64 overflow-hidden">
{/* Header */}
        <header className="bg-white border-b border-neutral-200 px-8 py-6">
          <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold text-neutral-900">Document Management</h1>
                <p className="text-neutral-500 mt-1">
                   {activeFolderId ? getCategoryName(activeFolderId) : "Browse all documents"}
                 </p>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="max-w-7xl mx-auto px-8 py-6">
            {/* Quick Stats */}
            <div className="grid grid-cols-1 md:grid-cols-1 gap-6 mb-8">
              <div className="modern-card">
                <div className="card-body p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-sm font-medium text-neutral-500 mb-2">Total Documents</p>
                      <div className="text-3xl font-bold text-neutral-900">
                        {loading ? (
                          <div className="w-6 h-6 border-2 border-primary-200 border-t-primary-600 rounded-full animate-spin inline-block align-middle"></div>
                        ) : (
                          totalDocuments.toLocaleString()
                        )}
                      </div>
                    </div>
                    <div className="w-14 h-14 bg-blue-50 rounded-xl flex items-center justify-center flex-shrink-0 ml-6">
                      <span className="text-blue-600 text-2xl">📄</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

{/* Upload Document Section - Admin Only */}
            {isAdmin && (
              <div className="bg-white rounded-xl shadow-md mb-8 border border-gray-200">
                <div className="p-6 border-b border-gray-200">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">Upload Document</h3>
                      <p className="text-sm text-gray-500">
                        {activeFolderId ? `Add document to ${getCategoryName(activeFolderId)}` : 'Add document to general collection'}
                      </p>
                    </div>
                    <div className="bg-green-50 text-green-700 px-3 py-1 rounded-full text-xs font-medium">
                      Admin Access
                    </div>
                  </div>
                </div>
                <div className="p-6">
                  <DocUploader 
                    folderId={activeFolderId} 
                    onUploaded={() => {
                      // Refresh document list and count after upload
                      console.log("Upload completed, refreshing document list...");
                      setRefreshKey(prev => {
                        console.log("Refresh key changing from", prev, "to", prev + 1);
                        return prev + 1;
                      }); // Force DocumentList to re-render and fetch
                      
                      const fetchTotalDocuments = async () => {
                        try {
                          const token = localStorage.getItem("token");
                          const res = await fetch(`${API}/api/documents/count`, {
                            headers: token ? { Authorization: `Bearer ${token}` } : undefined,
                          });
                          
                          if (res.ok) {
                            const data = await res.json();
                            setTotalDocuments(data.count || 0);
                          }
                        } catch (error) {
                          console.error("Error refreshing document count:", error);
                        }
                      };
                    fetchTotalDocuments();
                    }} 
                  />
                </div>
              </div>
            )}

            {/* Document List */}
            <DocumentList key={refreshKey} folderId={activeFolderId} />
          </div>
        </div>
      </main>
    </div>
  );
}
