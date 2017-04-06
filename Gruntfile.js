module.exports = function (grunt) {

  grunt.loadNpmTasks('grunt-mocha-istanbul');

  grunt.initConfig({
    mocha_istanbul: {
      coverage: {
        src: 'test'
      }
    }
  });

  grunt.registerTask('test', ['mocha_istanbul:coverage']);
};
