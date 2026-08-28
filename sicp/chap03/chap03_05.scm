(define (stream-car stream) (car stream))
(define (stream-cdr stream) (force (cdr stream)))

(define (stream-ref s n)
  (if (= n 0)
      (stream-car s)
      (stream-ref (stream-cdr s) (- n 1))))

(define-syntax cons-stream
  (syntax-rules ()
    ((cons-stream a b)
     (cons a (delay b)))))

(define stream-null? null?)
(define the-empty-stream '())

(define (stream-map proc . argstreams)
  (if (stream-null? (car argstreams))
      the-empty-stream
      (cons-stream
       (apply proc (map stream-car argstreams))
       (apply stream-map (cons proc (map stream-cdr argstreams))))))

(define (stream-for-each proc s)
  (if (stream-null? s)
      'done
      (begin (proc (stream-car s))
	     (stream-for-each proc (stream-cdr s)))))

(define (stream-filter pred stream)
  (cond ((stream-null? stream) the-empty-stream)
	((pred (stream-car stream))
	 (cons-stream (stream-car stream)
		      (stream-filter pred (stream-cdr stream))))
	(else (stream-filter pred (stream-cdr stream)))))

(define (stream-enumerate-interval low high)
  (if (> low high)
      the-empty-stream
      (cons-stream
       low
       (stream-enumerate-interval (+ low 1) high))))

(define (display-line x)
  (newline)
  (display x))

(define (display-stream s)
  (stream-for-each display-line s))

(define (print-stream-n s n)
  (if (or (= n 0) (stream-null? s))
      'done
      (begin (display-line (stream-car s))
	     (print-stream-n (stream-cdr s) (- n 1)))))

;; (define s (stream-enumerate-interval 1 100))
;; (display-stream s)


;; 3.51
(define (show x)
  (display-line x)
  x)

(define x (stream-map show (stream-enumerate-interval 0 10))) ;; output 0

(stream-ref x 5) ;; output 1-5
(stream-ref x 7) ;; only output 6-7


;; 这正是 3.51 要揭示的核心：
;; - 流的头部是立即求值的——cons-stream 展开成 (cons a (delay b))，a 在构造时就求值，所以定义 x 时 (show 0) 立即执行、打印 0。
;; - 尾部是惰性的——stream-ref x 5 按需逐个 force，因此才依次打印 1~5。
;; - 记忆化——stream-ref x 7 时 0~5 的 promise 已经算过并缓存，force 不再执行 show，只有 6、7 是新算的。
;; 建议注释补一句
;; (define x ...) 打印 0，这样答案才完整。

;; 3.52
(define sum 0)

(define (accum x)
  (set! sum (+ x sum))
  sum)

(define seq (stream-map accum (stream-enumerate-interval 1 20)))
(define y (stream-filter even? seq))
(define z (stream-filter (lambda (x) (= (remainder x 5) 0)) seq))
(stream-ref y 7) ;; output 136
(display-stream z) ;; output 10 15 45 55 105 120 190 210

(display-stream seq)
(display-stream z)

;; sum 210
;; 题目问"如果 delay 不记忆化（按 3.50/3.51 的朴素实现），sum 会是什么"。关键差异：
;; - 记忆化时，y 和 z 共享已算的 seq 项，每个元素只被 accum 一次。
;; - 不记忆化时，force 每次都重跑延迟过程。define z 时 seq 的 2、3 项会被重算（accum 2、accum 3 再执行一遍），所以 sum 会在每一步都偏大，最终不是 210，而是显著更大的值

;; sec 3.5.2

(define (integers-starting-from n)
  (cons-stream n (integers-starting-from (+ n 1))))

(define integers (integers-starting-from 1))

(define (divisible? x y) (= (remainder x y) 0))

(define no-sevens
  (stream-filter (lambda (x) (not (divisible? x 7)))
		 integers))

(define (fibgen a b)
  (cons-stream a (fibgen b (+ a b))))

(define fibs (fibgen 0 1))

(define (sieve stream)
  (cons-stream
   (stream-car stream)
   (sieve (stream-filter
	   (lambda (x)
	     (not (divisible? x (stream-car stream))))
	   (stream-cdr stream)))))

(define primes (sieve (integers-starting-from 2)))

(define ones (cons-stream 1 ones))

(define (add-streams s1 s2)
  (stream-map + s1 s2))

(define integers (cons-stream 1 (add-streams ones integers)))

(define fibs
  (cons-stream 0
	       (cons-stream 1
			    (add-streams (stream-cdr fibs)
					 fibs))))

;; 3.53
(define s (cons-stream 1 (add-streams s s))) ;; output {2^n}

;; 3.54
(define (mul-streams s1 s2)
  (stream-map * s1 s2))

(define factorials (cons-stream 1 (mul-streams factorials integers)))

;; 3.55
(define (partial-sums s)
  (cons-stream
   (stream-car s)
   (stream-map + (partial-sums s) (stream-cdr s))))

(define n (partial-sums integers))

(print-stream-n n 5)

(stream-ref n 0)
(stream-ref n 1)
(stream-ref n 2)
(stream-ref n 3)

;; 3.56
(define (merge s1 s2)
  (cond ((stream-null? s1) s2)
	((stream-null? s2) s1)
	(else
	 (let ((x1 (stream-car s1))
	       (x2 (stream-car s2)))
	   (cond ((< x1 x2)
		  (cons-stream x1 (merge (stream-cdr s1) s2)))
		 ((> x1 x2)
		  (cons-stream x2 (merge s1 (stream-cdr s2))))
	 (else
	  (cons-stream x1 (merge (stream-cdr s1) (stream-cdr s2)))))))))

(define (scale-stream stream factor)
  (stream-map (lambda (x) (* x factor)) stream))

(define S (cons-stream 1 (merge (scale-stream S 2)
				(merge (scale-stream S 3)
				       (scale-stream S 5)))))

(print-stream-n S 7)

;; 3.57
;; With memo-proc: n addition
;; Without memo-proc: increasing like fibs

;; 3.58

(define (expand num den radix)
  (cons-stream
   (quotient (* num radix) den)
   (expand (remainder (* num radix) den) den radix)))

(print-stream-n (expand 1 7 10) 10)

(print-stream-n (expand 3 8 10) 10)
