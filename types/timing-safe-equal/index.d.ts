declare module 'timing-safe-equal' {
  function timingSafeEqual(a: Buffer | NodeJS.TypedArray | DataView, b: Buffer | NodeJS.TypedArray | DataView): boolean;
  export = timingSafeEqual;
}
