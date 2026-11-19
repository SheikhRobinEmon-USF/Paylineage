// Types for the generated standalone validators.
export interface GeneratedValidator {
  (data: unknown): boolean;
  errors?: { message?: string }[] | null;
}
export const validateInput: GeneratedValidator;
export const validateOutput: GeneratedValidator;
