import { BadRequestException, CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { UserEntity } from 'src/modules/users/entities/user.entity';
import { META_ROLES } from '../decorators/role-protect.decorator';
import { ValidRoles } from '../interfaces/valid-roles.interface';

@Injectable()
export class UserRoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const validRoles: string[] = this.reflector.getAllAndOverride(META_ROLES, [
      context.getHandler(),
      context.getClass(),
    ]);

    const request = context.switchToHttp().getRequest();
    const user = request.user as UserEntity;

    if (!user) throw new BadRequestException('User not found');
    
    // Validación para cliente
    if (user.rol.rol_name === ValidRoles.client) {
      const paramId = request.params.id;
      if (paramId && parseInt(paramId, 10) !== user.id_user) {
        throw new ForbiddenException('You do not have permission to access this resource..');
      }
      return true;
    }

    // Si el rol del usuario no está permitido.
    if (!validRoles.includes(user.rol.rol_name)) {
      throw new ForbiddenException('you do not have permission to access this resource.');
    }

    return true;
  }
}
