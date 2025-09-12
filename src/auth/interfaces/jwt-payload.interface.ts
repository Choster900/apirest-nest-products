export interface JwtPayload {
    id: string;
    sessionVersion?: number; // Global session version when token was created
}
