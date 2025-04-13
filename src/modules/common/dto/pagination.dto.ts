import { Type } from "class-transformer";
import { IsOptional, IsPositive, Min } from "class-validator";

export class PaginationDto{
    @IsOptional()
    @Type(() => Number)
    limit?: number;

    @IsOptional()
    @Min(1)
    @Type(() => Number)
    page?: number;
}