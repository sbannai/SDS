import { useAuth } from "../../context/AuthContext";

interface MenuItem {
  id: string;
  label: string;
  folderId: number;
  icon?: string;
}

interface SidebarProps {
  activeFolderId: number | null;
  onSelectFolder: (folderId: number) => void;
}

export default function Sidebar({ activeFolderId, onSelectFolder }: SidebarProps) {
  const { user, logout } = useAuth();

  const baseMenus: Record<string, MenuItem[]> = {
    ADMIN: [
      { id: "admin", label: "Administration", folderId: 1, icon: "🏢" },
      { id: "staff", label: "Staff Records", folderId: 2, icon: "👥" },
      { id: "students", label: "Student Records", folderId: 3, icon: "🎓" },
      { id: "academics", label: "Academics", folderId: 4, icon: "📚" },
      { id: "exams", label: "Examinations", folderId: 5, icon: "📝" }
    ],
    STAFF: [
      { id: "staff", label: "Staff Records", folderId: 2, icon: "👥" },
      { id: "students", label: "Student Records", folderId: 3, icon: "🎓" }
    ],
    TEACHER: [
      { id: "students", label: "Student Records", folderId: 3, icon: "🎓" },
      { id: "academics", label: "Academics", folderId: 4, icon: "📚" },
      { id: "exams", label: "Examinations", folderId: 5, icon: "📝" }
    ]
  };

  const roleKey = (user?.role || "STAFF").toUpperCase();
  const menus = baseMenus[roleKey] || baseMenus["STAFF"];

  return (
    <div className="fixed left-0 top-0 w-64 bg-white border-r border-neutral-100 h-screen flex flex-col z-50">
      {/* Sidebar Header */}
      <div className="p-6 border-b border-neutral-100">
        <div className="mb-4">
          <h1 className="text-lg font-semibold text-neutral-900 mb-1">School DMS</h1>
          <p className="text-xs text-neutral-500">Document Management</p>
        </div>
        <div className="bg-neutral-50 rounded-lg px-3 py-2">
          <p className="text-sm font-medium text-neutral-900">{user?.name}</p>
          <p className="text-xs text-neutral-500 capitalize">{user?.role}</p>
        </div>
      </div>

      {/* Navigation Items */}
      <nav className="flex-1 overflow-y-auto p-4">
        <div className="space-y-1">
          {menus.map((item) => (
            <button
              key={item.id}
              onClick={() => onSelectFolder(item.folderId)}
              className={`w-full flex items-center justify-between px-4 py-3 rounded-lg text-left transition-all duration-200 group ${
                activeFolderId === item.folderId
                  ? 'bg-primary-50 text-primary-700 border-l-4 border-primary-600'
                  : 'text-neutral-700 hover:bg-neutral-50 hover:text-neutral-900'
              }`}
            >
              <div className="flex items-center space-x-3 flex-1">
                <div className={`text-base w-5 text-center ${
                  activeFolderId === item.folderId ? 'text-primary-600' : 'text-neutral-400 group-hover:text-neutral-600'
                }`}>
                  {item.icon}
                </div>
                <span className="font-medium text-sm">{item.label}</span>
              </div>
              <div className={`w-2 h-2 rounded-full ${
                activeFolderId === item.folderId ? 'bg-primary-600' : 'bg-transparent group-hover:bg-neutral-300'
              }`} />
            </button>
          ))}
        </div>
      </nav>

      {/* Sidebar Footer */}
      <div className="p-4 border-t border-neutral-100">
        <button
          onClick={logout}
          className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 bg-red-50 text-red-700 rounded-lg hover:bg-red-100 transition-colors duration-200 border border-red-200"
        >
          <span className="text-sm font-medium">Logout</span>
        </button>
      </div>
    </div>
  );
}
