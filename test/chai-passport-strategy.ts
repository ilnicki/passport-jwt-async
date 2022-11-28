import * as Test from 'chai-passport-strategy/lib/test';
import { Done } from 'mocha';
import { Strategy } from 'passport-strategy';

class DoneTest extends Test {
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

  public success(cb): this {
    super.success(this.wrap(cb));
    return this;
  }

  public fail(cb): this {
    super.fail(this.wrap(cb));
    return this;
  }

  public redirect(cb): this {
    super.redirect(this.wrap(cb));
    return this;
  }

  public pass(cb): this {
    super.pass(this.wrap(cb));
    return this;
  }

  public error(cb): this {
    super.error(this.wrap(cb));
    return this;
  }

  public req(cb): this {
    super.req(cb);
    return this;
  }

  public authenticate(options?: any): void {
    super.authenticate(options);
  }
}

export const use = (strategy: Strategy, done?: Done) =>
  new DoneTest(strategy, done);
