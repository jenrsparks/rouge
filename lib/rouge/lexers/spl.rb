# -*- coding: utf-8 -*- #
# frozen_string_literal: true

module Rouge
  module Lexers
    class XML < RegexLexer
      title "SPL"
      desc "Search Processing Language (SPL) for use with Splunk"
      tag 'spl'
      filenames '*.spl'
      mimetypes 'text/x-spl'

      def self.detect?(text)
        return true if text.doctype?
      end

      state :root do
        rule /[^<&]+/, Text
        rule /&\S*?;/, Name::Entity
        rule /<!\[CDATA\[.*?\]\]\>/, Comment::Preproc
        rule /<!--/, Comment, :comment
        rule /<\?.*?\?>/, Comment::Preproc
        rule /<![^>]*>/, Comment::Preproc

        # open tags
        rule %r(<\s*[\w:.-]+)m, Name::Tag, :tag

        # self-closing tags
        rule %r(<\s*/\s*[\w:.-]+\s*>)m, Name::Tag
      end

      state :comment do
        rule /[^-]+/m, Comment
        rule /-->/, Comment, :pop!
        rule /-/, Comment
      end

      state :tag do
        rule /\s+/m, Text
        rule /[\w.:-]+\s*=/m, Name::Attribute, :attr
        rule %r(/?\s*>), Name::Tag, :pop!
      end

      state :attr do
        rule /\s+/m, Text
        rule /".*?"|'.*?'|[^\s>]+/m, Str, :pop!
      end
    end
  end
end
