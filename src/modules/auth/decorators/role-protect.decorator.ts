import { SetMetadata } from '@nestjs/common';
import { ValidRoles } from '../interfaces/valid-roles.interface';


export const META_ROLES ='role'
export const RoleProtected = (...roles: ValidRoles[]) => {
  return SetMetadata(META_ROLES, roles)
}
