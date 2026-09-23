// cadesplugin.async_spawn: runs a generator that yields promises, as in cadesplugin_api.js 2.4.5.
// Sites written for old browsers drive the whole async API through it.

type Spawnable = (args: unknown[]) => Generator<unknown, unknown, unknown>;

export function asyncSpawn(generatorFunc: Spawnable, ...args: unknown[]): unknown {
  const generator = generatorFunc(args);
  function continuer(verb: "next" | "throw", arg?: unknown): unknown {
    let result: IteratorResult<unknown, unknown>;
    try {
      result = generator[verb](arg);
    } catch (err) {
      return Promise.reject(err);
    }
    if (result.done) return result.value;
    return Promise.resolve(result.value).then(onFulfilled, onRejected);
  }
  const onFulfilled = (value?: unknown) => continuer("next", value);
  const onRejected = (reason: unknown) => continuer("throw", reason);
  return onFulfilled();
}
