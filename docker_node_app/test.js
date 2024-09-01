var assert = require('assert')

function test() {
  assert.equal(1 * 5, 5);
}

if (module == require.main) require('test').run(test);