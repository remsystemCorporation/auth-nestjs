import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { UserEntity } from 'src/modules/users/entities/user.entity';
import { META_ROLES } from '../decorators/role-protect.decorator';
import { ValidRoles } from '../interfaces/valid-roles.interface';

@Injectable()
export class UserRoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const validRoles: string[] = this.reflector.getAllAndOverride(META_ROLES, [
      context.getHandler(),
      context.getClass(),
    ]) || [];

    const request = context.switchToHttp().getRequest<Request>();
    const user = request.user as UserEntity;

    // 1. Verificar que el usuario esté autenticado
    if (!user) {
      throw new UnauthorizedException('User not found in request');
    }

    // 2. Si no hay roles requeridos, permitir acceso
    if (validRoles.length === 0) return true;

    // 3. Validar acceso a recursos propios (si aplica)
    if (this.isAccessingOwnResource(request, user.idUser)) {
      return true;
    }

    // 4. Validar roles (versión corregida)
    // Asumiendo que user.role.rolName contiene el nombre del rol (ej: 'admin')
    if(!validRoles.includes(user.role.rolName as ValidRoles)){
      throw new ForbiddenException("You need one rol");
    }

    return true;
  }

  private isAccessingOwnResource(request: Request, userId: number): boolean {
    const requestedId = request.params.id;
    if (!requestedId) return false;

    // Comparar el ID del token con el ID solicitado
    return parseInt(requestedId, 10) === userId;
  }
}