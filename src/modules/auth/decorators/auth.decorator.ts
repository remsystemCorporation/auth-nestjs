import { applyDecorators, SetMetadata, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UserRoleGuard } from '../guards/user.guard';
import { ValidRoles } from '../interfaces/valid-roles.interface';
import { RoleProtected } from './role-protect.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

export function Auth (...roles: ValidRoles[]) {
  return applyDecorators(
    RoleProtected(...roles),
    UseGuards(AuthGuard(), UserRoleGuard, JwtAuthGuard)
  )
}
