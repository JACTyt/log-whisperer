import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(cleanup)

// jsdom does not implement layout APIs. Current Chrome returns a Promise from the scroll methods,
// which crashes React if an effect accidentally returns it — mimic that so tests catch it.
Element.prototype.scrollIntoView = () => Promise.resolve() as unknown as void
HTMLElement.prototype.focus = function () {
  return Promise.resolve() as unknown as void
}
