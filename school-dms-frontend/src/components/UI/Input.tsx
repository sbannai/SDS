import React from 'react';

interface InputProps {
  id?: string;
  type?: 'text' | 'email' | 'password' | 'number' | 'file';
  label?: string;
  placeholder?: string;
  value?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  className?: string;
  helperText?: string;
}

const Input: React.FC<InputProps> = ({
  id,
  type = 'text',
  label,
  placeholder,
  value,
  onChange,
  error,
  required = false,
  disabled = false,
  className = '',
  helperText
}) => {
  const inputClasses = `
    w-full px-4 py-3 border rounded-lg transition-all duration-200
    ${error 
      ? 'border-red-300 focus:border-red-500 focus:ring-red-500' 
      : 'border-neutral-300 focus:border-primary-500 focus:ring-primary-500'
    }
    ${disabled ? 'bg-neutral-100 cursor-not-allowed' : 'bg-white'}
    focus:outline-none focus:ring-2
    ${className}
  `;

  return (
    <div className="space-y-2">
      {label && (
        <label htmlFor={id} className="block text-sm font-medium text-neutral-700">
          {label}
          {required && <span className="text-red-500 ml-1">*</span>}
        </label>
      )}
      <input
        id={id}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        required={required}
        disabled={disabled}
        className={inputClasses}
      />
      {error && (
        <p className="text-sm text-red-600 flex items-center">
          <span className="mr-1">⚠</span>
          {error}
        </p>
      )}
      {helperText && !error && (
        <p className="text-sm text-neutral-500">{helperText}</p>
      )}
    </div>
  );
};

export default Input;