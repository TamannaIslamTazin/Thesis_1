/**
 * SSI Healthcare - Form Validation Hook
 * 
 * Custom React hook for form handling with Zod validation.
 * Provides real-time validation, field-level errors, and submission handling.
 */

'use client';

import * as React from 'react';
import { useState, useCallback, useMemo, ChangeEvent, FormEvent } from 'react';
import { z, ZodSchema } from 'zod';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseFormOptions<T extends ZodSchema> {
  schema: T;
  defaultValues?: Partial<z.infer<T>>;
  validateOnChange?: boolean;
  validateOnBlur?: boolean;
  onSubmit?: (data: z.infer<T>) => Promise<void> | void;
}

export interface FieldState {
  value: unknown;
  error: string | null;
  touched: boolean;
  dirty: boolean;
}

export interface FormState<T extends ZodSchema> {
  values: Partial<z.infer<T>>;
  errors: Record<string, string>;
  touched: Record<string, boolean>;
  isValid: boolean;
  isSubmitting: boolean;
  isSubmitted: boolean;
  submitCount: number;
}

export interface UseFormReturn<T extends ZodSchema> {
  // State
  values: Partial<z.infer<T>>;
  errors: Record<string, string>;
  touched: Record<string, boolean>;
  isValid: boolean;
  isSubmitting: boolean;
  isSubmitted: boolean;
  isDirty: boolean;
  
  // Field helpers
  register: (name: keyof z.infer<T>) => {
    value: unknown;
    onChange: (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => void;
    onBlur: () => void;
    name: string;
    'aria-invalid': boolean;
    'aria-describedby': string | undefined;
  };
  getFieldState: (name: keyof z.infer<T>) => FieldState;
  getFieldError: (name: keyof z.infer<T>) => string | null;
  
  // Actions
  setValue: (name: keyof z.infer<T>, value: unknown) => void;
  setValues: (values: Partial<z.infer<T>>) => void;
  setError: (name: keyof z.infer<T>, error: string) => void;
  clearError: (name: keyof z.infer<T>) => void;
  clearErrors: () => void;
  setTouched: (name: keyof z.infer<T>, touched?: boolean) => void;
  validate: () => boolean;
  validateField: (name: keyof z.infer<T>) => boolean;
  reset: (values?: Partial<z.infer<T>>) => void;
  handleSubmit: (e?: FormEvent) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Hook Implementation
// ---------------------------------------------------------------------------

type FormValues = Record<string, unknown>;

export function useForm<T extends ZodSchema>(
  options: UseFormOptions<T>
): UseFormReturn<T> {
  const {
    schema,
    defaultValues = {} as Partial<z.infer<T>>,
    validateOnChange = true,
    validateOnBlur = true,
    onSubmit,
  } = options;

  // State - use Record for internal state to allow indexing
  const [values, setValuesState] = useState<FormValues>(defaultValues as FormValues);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [touched, setTouchedState] = useState<Record<string, boolean>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [submitCount, setSubmitCount] = useState(0);
  
  // Track default values for dirty check
  const defaultValuesRef = React.useRef<FormValues>(defaultValues as FormValues);
  
  // Refs for volatile deps so setValue stays referentially stable
  const touchedRef = React.useRef(touched);
  touchedRef.current = touched;
  const validateOnChangeRef = React.useRef(validateOnChange);
  validateOnChangeRef.current = validateOnChange;

  // Derived state
  const isValid = useMemo(() => {
    return Object.keys(errors).length === 0;
  }, [errors]);

  const isDirty = useMemo(() => {
    return JSON.stringify(values) !== JSON.stringify(defaultValuesRef.current);
  }, [values]);

  // Validate entire form
  const validate = useCallback((): boolean => {
    const result = schema.safeParse(values);
    
    if (result.success) {
      setErrors({});
      return true;
    }
    
    const newErrors: Record<string, string> = {};
    for (const error of result.error.errors) {
      const path = error.path.join('.');
      if (!newErrors[path]) {
        newErrors[path] = error.message;
      }
    }
    
    setErrors(newErrors);
    return false;
  }, [schema, values]);

  // Validate single field
  const validateField = useCallback((name: keyof z.infer<T>): boolean => {
    // Try to validate just the field by creating a partial schema
    // This is a simplified approach - in production you might want
    // to use schema.pick() if available or validate the whole object
    const result = schema.safeParse(values);
    
    if (result.success) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[String(name)];
        return newErrors;
      });
      return true;
    }
    
    // Find errors for this specific field
    const fieldErrors = result.error.errors.filter(
      err => err.path[0] === name
    );
    
    if (fieldErrors.length > 0) {
      setErrors(prev => ({
        ...prev,
        [String(name)]: fieldErrors[0].message,
      }));
      return false;
    }
    
    // No errors for this field
    setErrors(prev => {
      const newErrors = { ...prev };
      delete newErrors[String(name)];
      return newErrors;
    });
    return true;
  }, [schema, values]);

  // Set single value
  const setValue = useCallback((name: keyof z.infer<T>, value: unknown) => {
    setValuesState(prev => ({
      ...prev,
      [name]: value,
    }));
    
    if (validateOnChangeRef.current && touchedRef.current[String(name)]) {
      // Defer validation to next tick to ensure state is updated
      setTimeout(() => validateField(name), 0);
    }
  }, [validateField]);

  // Set multiple values
  const setValues = useCallback((newValues: Partial<z.infer<T>>) => {
    setValuesState(prev => ({
      ...prev,
      ...newValues,
    }));
  }, []);

  // Set error for a field
  const setError = useCallback((name: keyof z.infer<T>, error: string) => {
    setErrors(prev => ({
      ...prev,
      [String(name)]: error,
    }));
  }, []);

  // Clear error for a field
  const clearError = useCallback((name: keyof z.infer<T>) => {
    setErrors(prev => {
      const newErrors = { ...prev };
      delete newErrors[String(name)];
      return newErrors;
    });
  }, []);

  // Clear all errors
  const clearErrors = useCallback(() => {
    setErrors({});
  }, []);

  // Set touched for a field
  const setTouched = useCallback((name: keyof z.infer<T>, isTouched = true) => {
    setTouchedState(prev => ({
      ...prev,
      [String(name)]: isTouched,
    }));
  }, []);

  // Reset form
  const reset = useCallback((newValues?: Partial<z.infer<T>>) => {
    setValuesState((newValues ?? defaultValuesRef.current) as FormValues);
    setErrors({});
    setTouchedState({});
    setIsSubmitting(false);
    setIsSubmitted(false);
  }, []);

  // Handle form submission
  const handleSubmit = useCallback(async (e?: FormEvent) => {
    if (e) {
      e.preventDefault();
    }
    
    setIsSubmitting(true);
    setSubmitCount(prev => prev + 1);
    
    // Mark all fields as touched
    const allTouched: Record<string, boolean> = {};
    Object.keys(values).forEach(key => {
      allTouched[key] = true;
    });
    setTouchedState(allTouched);
    
    // Validate
    const isFormValid = validate();
    
    if (!isFormValid) {
      setIsSubmitting(false);
      return;
    }
    
    // Call onSubmit
    if (onSubmit) {
      try {
        await onSubmit(values as z.infer<T>);
        setIsSubmitted(true);
      } catch (error) {
        // If onSubmit throws, set a general error
        if (error instanceof Error) {
          setErrors(prev => ({
            ...prev,
            _form: error.message,
          }));
        }
      }
    }
    
    setIsSubmitting(false);
  }, [values, validate, onSubmit]);

  // Register a field (for use with native inputs)
  const register = useCallback((name: keyof z.infer<T>) => {
    const fieldName = String(name);
    const hasError = !!errors[fieldName];
    const value = values[fieldName];
    
    return {
      value: (value ?? '') as string,
      name: fieldName,
      onChange: (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
        const newValue = e.target.type === 'checkbox' 
          ? (e.target as HTMLInputElement).checked 
          : e.target.value;
        setValue(name, newValue);
      },
      onBlur: () => {
        setTouched(name, true);
        if (validateOnBlur) {
          validateField(name);
        }
      },
      'aria-invalid': hasError,
      'aria-describedby': hasError ? `${fieldName}-error` : undefined,
    };
  }, [values, errors, setValue, setTouched, validateOnBlur, validateField]);

  // Get field state
  const getFieldState = useCallback((name: keyof z.infer<T>): FieldState => {
    const fieldName = String(name);
    const value = values[fieldName];
    const defaultValue = defaultValuesRef.current[fieldName];
    return {
      value,
      error: errors[fieldName] || null,
      touched: touched[fieldName] || false,
      dirty: value !== defaultValue,
    };
  }, [values, errors, touched]);

  // Get field error (only if touched or submitted)
  const getFieldError = useCallback((name: keyof z.infer<T>): string | null => {
    const fieldName = String(name);
    if (!touched[fieldName] && !isSubmitted && submitCount === 0) {
      return null;
    }
    return errors[fieldName] || null;
  }, [errors, touched, isSubmitted, submitCount]);

  return {
    // State - cast values to the expected type
    values: values as Partial<z.infer<T>>,
    errors,
    touched,
    isValid,
    isSubmitting,
    isSubmitted,
    isDirty,
    
    // Field helpers
    register,
    getFieldState,
    getFieldError,
    
    // Actions
    setValue,
    setValues,
    setError,
    clearError,
    clearErrors,
    setTouched,
    validate,
    validateField,
    reset,
    handleSubmit,
  };
}

// ---------------------------------------------------------------------------
// Field Error Component
// ---------------------------------------------------------------------------

interface FieldErrorProps {
  name: string;
  error: string | null;
  className?: string;
}

export function FieldError({ name, error, className = '' }: FieldErrorProps) {
  if (!error) return null;
  
  return (
    <p
      id={`${name}-error`}
      className={`text-sm text-destructive mt-1 ${className}`}
      role="alert"
    >
      {error}
    </p>
  );
}
