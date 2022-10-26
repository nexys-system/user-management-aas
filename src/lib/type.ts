export enum AuthenticationType {
  google = 2
}

export interface Profile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
}

export type Locale = any;
