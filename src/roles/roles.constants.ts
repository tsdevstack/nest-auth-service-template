/**
 * Custom roles of this product.
 *
 * Every user has one system role (`systemRole`: `USER` or `ADMIN`, owned by
 * the framework) and any number of custom roles (`roles`). Declare your custom
 * roles here; the admin role API rejects any role not listed.
 *
 * Both kinds end up in the JWT (`systemRole` and `roles` claims) and are
 * checked by `@Roles()` from `@tsdevstack/nest-common` in any service:
 *
 * ```typescript
 * export const CUSTOM_ROLES: readonly string[] = ['EDITOR', 'BILLING'];
 *
 * @Roles('EDITOR')
 * @Get('drafts')
 * drafts() {}
 * ```
 *
 * A custom role must not reuse a system role name (`USER`, `ADMIN`): the
 * role API rejects it, because `@Roles('ADMIN')` would match it.
 */
export const CUSTOM_ROLES: readonly string[] = [];
