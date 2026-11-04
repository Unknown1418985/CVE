import { Controller, Get } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';

import {
  PERMISSION_DESCRIPTIONS,
  PERMISSIONS,
  PRIVILEGED_ROLES,
  ROLE_LABELS,
  ROLE_PERMISSIONS,
  ROLES,
  type PermissionDescription,
  type RoleDescription,
} from '@cve/contracts';

/** Read-only RBAC catalog. Role membership is managed through `/users/:id/roles`. */
@ApiTags('access-control')
@ApiBearerAuth()
@Controller()
export class RolesController {
  @Get('roles')
  @ApiOperation({ summary: 'Platform roles and the permissions each one grants' })
  roles(): { data: RoleDescription[] } {
    return {
      data: ROLES.map((role) => ({
        role,
        label: ROLE_LABELS[role],
        privileged: PRIVILEGED_ROLES.includes(role),
        permissions: [...ROLE_PERMISSIONS[role]],
      })),
    };
  }

  @Get('permissions')
  @ApiOperation({ summary: 'Permission catalog' })
  permissions(): { data: PermissionDescription[] } {
    return {
      data: PERMISSIONS.map((permission) => ({
        permission,
        description: PERMISSION_DESCRIPTIONS[permission],
      })),
    };
  }
}
