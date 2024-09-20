export class AppError extends Error {
    statusCode: number;
    status: string;
    isOperational: boolean;
  
    constructor(message: string, statusCode: number) {
      super(message);
      this.statusCode = statusCode;
      this.status = String(statusCode).startsWith("4") ? "error" : "failure";
      this.isOperational = true; // TODO: If not needed then remove
  
      // Set the prototype explicitly to maintain correct instanceof behavior
      Object.setPrototypeOf(this, AppError.prototype);
    }
  }
  