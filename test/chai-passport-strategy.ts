// @ts-ignore
import * as Test from 'chai-passport-strategy/lib/test';
import { Request } from 'express';
import { Done } from 'mocha';
import { Strategy } from 'passport-strategy';

class DoneTest extends (Test as any) {
  constructor(strategy: Strategy, private readonly done?: Done) {
    super(strategy);
  }

  private wrap<P extends Array<any>>(
    fn: (...args: P) => void
  ): (...args: P) => void {
    return this.done
      ? (...params: P): void => {
          try {
            fn(...params);
            this.done?.();
          } catch (err) {
            this.done?.(err);
          }
        }
      : fn;
  }

  public success(cb: (user: any, info: any) => void): this {
    super.success(this.wrap(cb));
    return this;
  }

  public fail(cb: (challenge: Error, status: number) => void): this {
    super.fail(this.wrap(cb));
    return this;
  }

  public redirect(cb: (url: string, status: number) => void): this {
    super.redirect(this.wrap(cb));
    return this;
  }

  public pass(cb: () => void): this {
    super.pass(this.wrap(cb));
    return this;
  }

  public error(cb: (err: Error) => void): this {
    super.error(this.wrap(cb));
    return this;
  }

  public req(cb: (req: Request, ready: () => void) => void): this {
    super.req(cb);
    return this;
  }

  public authenticate(options?: any): void {
    super.authenticate(options);
  }
}

export const use = (strategy: Strategy, done?: Done) =>
  new DoneTest(strategy, done);
