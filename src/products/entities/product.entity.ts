import { BeforeInsert, BeforeUpdate, Entity } from "typeorm";
import { Column, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Product {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column('text', {
        unique: true
    })
    title: string;

    @Column('float', {
        default: 0
    })
    price: number;

    @Column({
        type: 'text',
        nullable: true
    })
    description: string;


    @Column('text', {
        unique: true
    })
    slug: string

    @Column('text', {
        array: true
    })
    sizes: string[]

    @Column('text')
    gender: string;

    @Column('text', {
        array: true,
        default: []
    })
    tags: string[]

    @BeforeInsert()
    checkSlugInsert() {
        if (!this.slug) {
            this.slug = this.title
                .toLowerCase()
                .replaceAll(' ', '_')
                .replaceAll("'", '')
        }

        this.slug = this.slug
            .toLowerCase()
            .replaceAll(' ', '_')
            .replaceAll("'", '')

    }

    @BeforeUpdate()
    checkSlugActyalizar() {

        this.slug = this.slug
            .toLowerCase()
            .replaceAll(' ', '_')
            .replaceAll("'", '')

    }

}
