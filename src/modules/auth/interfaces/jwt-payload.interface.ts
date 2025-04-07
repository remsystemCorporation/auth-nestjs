export interface JwtPayload {
    sub: number;
    email: string;
    rol:string[],
    jti:string
  }