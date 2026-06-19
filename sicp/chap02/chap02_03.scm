(define (memq item x)
  (cond ((null? x) #f)
	((eq? item (car x)) x)
	(else (memq item (cdr x)))))

;; exec 2.53
(list 'a 'b 'c)               ;; (a b c) 没有引号
(list (list 'george))         ;; ((george)) 也没有引号
(cdr '((x1 x2) (y1 y2)))      ;; ((y1 y2))
(cadr '((x1 x2) (y1 y2)))     ;; (y1 y2)
(pair? (car '(a short list))) ;; #f

(memq 'red '((red shoe) (blue socks))) ;; #f
(memq 'red '(red shoe blud sockes))    ;; (red shoe blud socks)

;; exec 2.54
(define (equal? x y)
  (if (and (pair? x) (pair? y))
      (and (equal? (car x) (car y))
	   (equal? (cdr x) (cdr y)))
      (eq? x y)))

(equal? '(this is a list) '(this is a list))
(equal? '(this is a list) '(this (is a) list))

(equal? 'a 'a)
(equal? 'a '(a))

;; exec 2.55
;; 因为 ''xzdadfa 的结果就是 (quote xzdadfa) 再对它取 car 就是 quota

;; sec 2.3.2
(define (=number? x y)
  (and (number? x) (= x y)))

(define (variable? x) (symbol? x))
(define (same-variable? v1 v2)
  (and (variable? v1) (variable? v2) (eq? v1 v2)))

(define (make-sum a1 a2)
  (cond ((=number? a1 0) a2)
	((=number? a2 0) a1)
	((and (number? a1) (number? a2)) (+ a1 a2))
	(else (list '+ a1 a2))))
(define (sum? expr)
  (and (pair? expr) (eq? (car expr) '+)))
(define (addend expr) (cadr expr))
(define (augend expr) (caddr expr))

(define (make-product m1 m2)
  (cond ((or (=number? m1 0) (=number? m2 0)) 0)
	((=number? m1 1) m2)
	((=number? m2 1) m1)
	((and (number? m1) (number? m2)) (* m1 m2))
	(else (list '* m1 m2))))
(define (product? expr)
  (and (pair? expr) (eq? (car expr) '*)))
(define (multiplier expr) (cadr expr))
(define (multiplicand expr) (caddr expr))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	(else (error "unknown expression type -- DERIV" expr))))

(deriv '(+ x 1) 'x)
(deriv '(* x y) 'x)
(deriv '(* (* x y) (+ x 3)) 'x)

;; exec 2.56
(define (exponentiation? expr)
  (eq? (car expr) '**))
(define (base expr) (cadr expr))
(define (exponent expr) (caddr expr))
(define (make-exponentiation b ex)
  (cond ((= ex 0) 1)
	((= ex 1) b)
	(else (list '** b ex))))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	((exponentiation? expr)
	 (make-product (exponent expr)
		       (make-product (make-exponentiation (base expr) (- (exponent expr) 1))
				     (deriv (base expr) var))))
	(else (error "unknown expression type -- DERIV" expr))))

;; exec 2.57
(define (augend expr)
  (if (= (length (cddr expr)) 1)
      (caddr expr)
      (cons '+ (cddr expr))))

(define (multiplicand expr)
  (if (= (length (cddr expr)) 1)
      (caddr expr)
      (cons '* (cddr expr))))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	((exponentiation? expr)
	 (make-product (exponent expr)
		       (make-product (make-exponentiation (base expr) (- (exponent expr) 1))
				     (deriv (base expr) var))))
	(else (error "unknown expression type -- DERIV" expr))))

(deriv '(* x y (+ x 3)) 'x)
(deriv '(* 1 2 3 4 5 x) 'x)

;; exec 2.58
(define (sum? expr)
  (and (pair? expr) (eq? (cadr expr) '+)))

(define (addend expr) (car expr))
(define (augend expr)
  (if (null? (cdddr expr))
      (caddr expr)
      (cddr expr)))

(define (make-sum a1 a2)
  (cond ((=number? a2 0) a1)
	((=number? a1 0) a2)
	((and (number? a1) (number? a2)) (+ a1 a2))
	(else (list a1 '+ a2))))

(define (product? expr)
  (and (pair? expr) (eq? (cadr expr) '*)))

(define (multiplier expr) (car expr))
(define (multiplicand expr)
  (if (null? (cdddr expr))
      (caddr expr)
      (cddr expr)))

(define (make-product m1 m2)
  (cond ((or (=number? m1 0) (=number? m2 0)) 0)
	((=number? m1 1) m2)
	((=number? m2 1) m1)
	((and (number? m1) (number? m2)) (* m1 m2))
	(else (list m1 '* m2))))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	(else (error "unknown expression type -- DERIV" expr))))

(define sample '(x * (x * y)))

;; sec 2.3.3
(define (element-of-set? x set)
  (cond ((null? set) #f)
	((equal? x (car set)) #t)
	(else (element-of-set? x (cdr set)))))

(define (adjoin-set x set)
  (if (element-of-set? x set)
      set
      (cons x set)))

(define (intersection-set set1 set2)
  (cond ((or (null? set1) (null? set2)) '())
	((element-of-set? (car set1) set2)
	 (cons (car set1) (intersection-set (cdr set1) set2)))
	(else (intersection-set (cdr set1) set2))))

;; exec 2.59
(define (union-set set1 set2)
  (cond ((null? set1) set2)
	((element-of-set? (car set1) set2)
	 (union-set (cdr set1) set2))
	(else (cons (car set1) (union-set (cdr set1) set2)))))

;; section 2.3.3
(define (element-of-set? x set)
  (cond ((null? set) #f)
	((= x (car set)) #t)
	((< x (car set)) #f)
	(else (element-of-set? x (cdr set)))))

(define (intersection-set set1 set2)
  (if (or (null? set1) (null? set2)) '()
      (let ((x1 (car set1)) (x2 (car set2)))
	(cond ((= x1 x2)
	       (cons x1 (intersection-set (cdr set1) (cdr set2))))
	      ((< x1 x2) (intersection-set (cdr set1) set2))
	      ((< x2 x1) (intersection-set set1 (cdr set2)))))))

;; exec 2.61
(define (adjoin-set x set)
  (if (null? set)
      (cons x '())
      (cond ((= x (car set)) set)
	    ((< x (car set))
	     (cons x set))
	    ((> x (car set))
	     (cons (car set) (adjoin-set x (cdr set)))))))

(adjoin-set 1 (list 1 2 3 4 5))
(adjoin-set 2 (list 1 3 4 5 6))
(adjoin-set 6 (list 1 2 3 4 5))

;; exec 2.62
(define (union-set set1 set2)
  (cond ((null? set1) set2)
	((null? set2) set1)
	(else (let ((x1 (car set1)) (x2 (car set2)))
		(cond ((= x1 x2) (cons x1 (union-set (cdr set1) (cdr set2))))
		      ((> x1 x2) (cons x2 (union-set set1 (cdr set2))))
		      ((< x1 x2) (cons x1 (union-set (cdr set1) set2))))))))

;; tree
(define (entry tree) (car tree))
(define (left-branch tree) (cadr tree))
(define (right-branch tree) (caddr tree))
(define (make-tree entry left right)
  (list entry left right))

(define (element-of-set? x set)
  (cond ((null? set) #f)
	((= x (entry set)) #t)
	((< x (entry set)) (element-of-set? x (left-branch set)))
	((> x (entry set)) (element-of-set? x (right-branch set)))))

;; exec 2.63
(define t1 (make-tree 3 (make-tree 1 '() '()) (make-tree 5 '() '())))
(define t2 (make-tree 9 '() (make-tree 11 '() '())))
(define t (make-tree 7 t1 t2))

(define (tree->list-1 tree)
  (if (null? tree)
      '()
      (append (tree->list-1 (left-branch tree))
	      (cons (entry tree)
		    (tree->list-1 (right-branch tree))))))

(tree->list-1 t)

(define (tree->list-2 tree)
  (define (copy-to-list tree result-list)
    (if (null? tree)
	result-list
	(copy-to-list (left-branch tree)
		      (cons (entry tree)
			    (copy-to-list (right-branch tree)
					  result-list)))))
  (copy-to-list tree '()))

(tree->list-2 t)
;; a) 两个过程生成的列表相同，都生成升序列表；(right)
;; b) 时间复杂度相同，但是第二个迭代的会更快；(wrong)

;; exec 2.64
(define (partial-tree elts n)
  (if (= n 0)
      (cons '() elts)
      (let ((left-size (quotient (- n 1) 2)))
	(let ((left-result (partial-tree elts left-size)))
	  (let ((left-tree (car left-result))
		(non-left-elts (cdr left-result))
		(right-size (- n (+ left-size 1))))
	    (let ((this-entry (car non-left-elts))
		  (right-result (partial-tree (cdr non-left-elts) right-size)))
	      (let ((right-tree (car right-result))
		    (remaining-elts (cdr right-result)))
		(cons (make-tree this-entry left-tree right-tree)
		      remaining-elts))))))))

(define (list->tree elements)
  (car (partial-tree elements (length elements))))

;; a) partial-tree 不断平分列表，最后到空列表再从叶节点构造树，所以几乎每个树都是平衡的。(1 3 5 7 9 11) 生成的树是 (5 (1 '() (3 '() '())) (9 (7 '() '()) (11 '() '()))); （right）
;; b) O(n*log(n)) （wrong）

;; exec 2.65
;; 1. tree->list-2 把两棵树转成有序列表 — O(n)
;; 2. 用 2.62 的 union-set / 2.61 的 intersection-set（有序列表版本）合并 — O(n)
;; 3. list->tree 把结果转回平衡树 — O(n)
;;
;; 具体代码跳过了

;; exec 2.66
(define (lookup key records)
  (cond ((null? records) #f)
	((= key (entry records))
	 (entry records))
	((< key (entry records))
	 (lookup key (left-branch records)))
	((> key (entry records))
	 (lookup key (right-branch records)))))

;; sec 2.3.4
(define (make-leaf symbol weight)
  (list 'leaf symbol weight))

(define (leaf? obj)
  (eq? (car obj) 'leaf))

(define (symbol-leaf x) (cadr x))
(define (weight-leaf x) (caddr x))

(define (symbols tree)
  (if (leaf? tree)
      (list (symbol-leaf tree))
      (caddr tree)))

(define (weight tree)
  (if (leaf? tree)
      (weight-leaf tree)
      (cadddr tree)))

(define (left-branch tree) (car tree))
(define (right-branch tree) (cadr tree))

(define (make-code-tree left right)
  (list left
	right
	(append (symbols left) (symbols right))
	(+ (weight left) (weight right))))

(define (choose-branch bit branch)
  (cond ((= bit 0) (left-branch branch))
	((= bit 1) (right-branch branch))
	(else (error "bad-bit -- CHOOSE-BRANCH" bit))))

(define (decode bits tree)
  (define (decode-1 bits current-branch)
    (if (null? bits) '()
	(let ((next-branch (choose-branch (car bits) current-branch)))
	  (if (leaf? next-branch)
	      (cons (symbol-leaf next-branch)
		    (decode-1 (cdr bits) tree))
	      (decode-1 (cdr bits) next-branch)))))
  (decode-1 bits tree))

(define (adjoin-set x set)
  (cond ((null? set) (list x))
	((< (weight x) (weight (car set))) (cons x set))
	(else (cons (car set)
		    (adjoin-set x (cdr set))))))

(define (make-leaf-set pairs)
  (if (null? pairs) '()
      (let ((pair (car pairs)))
	(adjoin-set (make-leaf (car pair) (cadr pair))
		    (make-leaf-set (cdr pairs))))))

;; exec 2.67
(define exec-tree
  (make-code-tree (make-leaf 'A 4)
		  (make-code-tree
		   (make-leaf 'B 2)
		   (make-code-tree (make-leaf 'D 1)
				   (make-leaf 'C 1)))))

(define simple-message '(0 1 1 0 0 1 0 1 0 1 1 1 0))

(decode simple-message exec-tree) ;; A D A B B C A

;; exec 2.68
(define (in-set? sym symbols)
  (cond ((null? symbols) #f)
	((eq? sym (car symbols)) #t)
	(else (in-set? sym (cdr symbols)))))

(define (encode-symbol sym tree)
  (cond ((not (in-set? sym (symbols tree)))
	 (error "unknown symbol -- ENCODE-SYMBOL" sym))
	((leaf? tree) '())
	((in-set? sym (symbols (left-branch tree)))
	 (cons 0
	       (encode-symbol sym (left-branch tree))))
	(else
	 (cons 1
	       (encode-symbol sym (right-branch tree))))))

(define (encode message tree)
  (if (null? message) '()
      (append (encode-symbol (car message) tree)
	      (encode (cdr message) tree))))

(define m (decode simple-message exec-tree))
(encode m exec-tree)

;; exec 2.69
(define (generate-huffman-tree pairs)
  (successive-merge (make-leaf-set pairs)))

(define (successive-merge leaves)
  (if (null? (cdr leaves))
      (car leaves)
      (successive-merge
       (adjoin-set (make-code-tree (car leaves) (cadr leaves))
		   (cddr leaves)))))

;; --- test ---

;; helper: weighted path length (sum of freq * codelen for each symbol)
(define (weighted-path-length tree)
  (define (depth sym branch d)
    (if (leaf? branch)
	(if (eq? sym (symbol-leaf branch)) d 0)
	(+ (depth sym (left-branch branch) (+ d 1))
	   (depth sym (right-branch branch) (+ d 1)))))
  (define (sum-pair pair tree)
    (* (cadr pair) (depth (car pair) tree 0)))
  (apply + (map (lambda (p) (sum-pair p tree))
		(list (list 'A 8) (list 'B 3)
		      (list 'C 1) (list 'D 1)
		      (list 'E 1) (list 'F 1)
		      (list 'G 1) (list 'H 1)))))

(define book-pairs '((A 8) (B 3) (C 1) (D 1) (E 1) (F 1) (G 1) (H 1)))

(define tree-269 (generate-huffman-tree book-pairs))

;; round-trip encode/decode
(define msg-269 '(A D A B B C A))
(define bits-269 (encode msg-269 tree-269))

(display "--- exec 2.69 ---") (newline)
(display "message: ") (display msg-269) (newline)
(display "bits:    ") (display bits-269) (newline)
(display "decode:  ") (display (decode bits-269 tree-269)) (newline)
(display "WPL:     ") (display (weighted-path-length tree-269)) (newline)  ;; should be 44

;; exec 2.70
(define table (list
	       (list 'A 2)
	       (list 'NA 16)
	       (list 'BOOM 1)
	       (list 'SHA 3)
	       (list 'GET 2)
	       (list 'YIP 9)
	       (list 'JOB 2)
	       (list 'WAH 1)))
(define lyric-tree (generate-huffman-tree table))
(define lyric '(GET A JOB SHA NA NA NA))

(encode lyric lyric-tree)

;; exec 2.71
;; n=5, 最频繁: 1位，最低频: 4位
;; n=10, 最频繁: 1位，最低频: 9位

;; exec 2.72
;; 编码最频繁的符号：\theta(n) ，因为要检查当前符号是否在符号表中
;; 编码最不频繁的符号: \theta(n^2)
