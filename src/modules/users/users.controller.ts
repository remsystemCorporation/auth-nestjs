import { Controller, Get, Post, Body, Patch, Param, Delete, Query } from '@nestjs/common';
import { UsersService } from './users.service';
import { Auth } from '../auth/decorators/auth.decorator';
import { ValidRoles } from '../auth/interfaces/valid-roles.interface';
import { PaginationDto } from '../common/dto/pagination.dto';
import { UserEntity } from './entities/user.entity';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('all')
  @Auth(ValidRoles.Admin, ValidRoles.Super)
  async findAll( @Query() paginationDto: PaginationDto ): Promise<{ users: UserEntity[]; total: number }> {
    const {total, users} = await this.usersService.findAllUser(paginationDto);
    return {total, users};
  }

  @Get('all/public')
  async findAllPublic( @Query() paginationDto: PaginationDto ): Promise<{ users: UserEntity[]; total: number }> {
    const {total, users} = await this.usersService.findAllUser(paginationDto);
    return {total, users};
  }

}
