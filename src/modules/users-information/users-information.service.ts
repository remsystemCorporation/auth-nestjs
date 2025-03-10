import { Injectable } from '@nestjs/common';
import { CreateUsersInformationDto } from './dto/create-users-information.dto';

@Injectable()
//TODO: SERVICE USERS INFORMATION
export class UsersInformationService {
  create(createUsersInformationDto: CreateUsersInformationDto) {
    return 'This action adds a new usersInformation';
  }

  findAll() {
    return `This action returns all usersInformation`;
  }

  findOne(id: number) {
    return `This action returns a #${id} usersInformation`;
  }


  remove(id: number) {
    return `This action removes a #${id} usersInformation`;
  }
}
