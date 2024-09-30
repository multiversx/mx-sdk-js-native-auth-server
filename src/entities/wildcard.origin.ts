export class WildcardOrigin {
  constructor(init?: Partial<WildcardOrigin>) {
    Object.assign(this, init);
  }

  protocol: string = '';

  domain: string = '';
}
